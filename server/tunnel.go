package server

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/saschazesiger/Z-Dash/server/cloudflare"
)

// The tunnel's API: the shell's tunnel settings (tunnel.js) talk to it.
// Setup and removal run in the background; the page polls GET
// /api/cloudflare for Status().Job while they run.

func (a *App) cloudflarePayload(r *http.Request) map[string]any {
	id := Who(r)
	return map[string]any{
		"status":      a.cf.Status(),
		"tokenUrl":    a.cf.TokenURL(),
		"permissions": cloudflare.Permissions(),
		"bypass":      a.cf.BypassPaths(),
		"via":         id.Via,
		"email":       id.Email,
	}
}

func (a *App) cloudflareStatus(w http.ResponseWriter, r *http.Request) {
	WriteJSON(w, http.StatusOK, a.cloudflarePayload(r))
}

// cloudflareCheck validates an API token and lists its domains. An empty
// token checks the stored one, for a repair.
func (a *App) cloudflareCheck(w http.ResponseWriter, r *http.Request) {
	var body struct {
		APIToken string `json:"apiToken"`
	}
	if !Decode(w, r, &body) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	info, err := a.cf.Check(ctx, body.APIToken)
	if err != nil {
		WriteFieldError(w, "apiToken", sentence(err.Error()))
		return
	}
	WriteJSON(w, http.StatusOK, info)
}

type setupBody struct {
	APIToken string   `json:"apiToken"`
	ZoneID   string   `json:"zoneId"`
	Hostname string   `json:"hostname"`
	Emails   []string `json:"emails"`
	Replace  bool     `json:"replace"`
}

// cloudflareSetup starts the setup, or a repair, in the background.
func (a *App) cloudflareSetup(w http.ResponseWriter, r *http.Request) {
	var body setupBody
	if !Decode(w, r, &body) {
		return
	}
	if err := keepsOwnAddress(r, body.Emails); err != nil {
		WriteFieldError(w, "emails", sentence(err.Error()))
		return
	}
	req := cloudflare.SetupRequest{APIToken: body.APIToken, ZoneID: body.ZoneID, Hostname: body.Hostname,
		Emails: body.Emails, Replace: body.Replace}
	if err := a.cf.StartSetup(req); err != nil {
		WriteError(w, http.StatusBadRequest, sentence(err.Error()))
		return
	}
	a.hub.notify("cloudflare")
	go a.watchJob()
	WriteJSON(w, http.StatusOK, a.cloudflarePayload(r))
}

// cloudflareEmails changes who may sign in through the tunnel.
func (a *App) cloudflareEmails(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Emails []string `json:"emails"`
	}
	if !Decode(w, r, &body) {
		return
	}
	if err := keepsOwnAddress(r, body.Emails); err != nil {
		WriteFieldError(w, "emails", sentence(err.Error()))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	if err := a.cf.SetEmails(ctx, body.Emails); err != nil {
		WriteFieldError(w, "emails", sentence(err.Error()))
		return
	}
	a.hub.notify("cloudflare")
	WriteJSON(w, http.StatusOK, a.cloudflarePayload(r))
}

// cloudflareRemove deletes the tunnel and what belongs to it on Cloudflare,
// in the background.
func (a *App) cloudflareRemove(w http.ResponseWriter, r *http.Request) {
	if err := a.cf.StartRemove(); err != nil {
		WriteError(w, http.StatusConflict, sentence(err.Error()))
		return
	}
	a.hub.notify("cloudflare")
	go a.watchJob()
	WriteJSON(w, http.StatusOK, a.cloudflarePayload(r))
}

// watchJob tells the pages about a running job's steps, so the settings
// follow it on the event stream as well as by polling.
func (a *App) watchJob() {
	last := ""
	for {
		st := a.cf.Status()
		now := st.Job.Step + "|" + strings.Join(st.Job.Done, "|")
		if now != last {
			last = now
			a.hub.notify("cloudflare")
		}
		if !st.Job.Running {
			a.hub.notify("cloudflare")
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// keepsOwnAddress refuses a list of addresses that would lock out the
// person who sends it through the tunnel.
func keepsOwnAddress(r *http.Request, emails []string) error {
	id := Who(r)
	if id.Via != "tunnel" || id.Email == "" {
		return nil
	}
	for _, e := range emails {
		if strings.EqualFold(strings.TrimSpace(e), id.Email) {
			return nil
		}
	}
	return errors.New("keep your own address (" + id.Email + ") on the list: without it, you would lock yourself out. " +
		"To take it off, do it on the local address")
}

// sentence starts a message of the cloudflare package with a capital letter
// and ends it with a full stop, as the shell shows it.
func sentence(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	s = strings.ToUpper(s[:1]) + s[1:]
	if !strings.HasSuffix(s, ".") && !strings.HasSuffix(s, "?") && !strings.HasSuffix(s, "!") {
		s += "."
	}
	return s
}
