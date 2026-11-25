package cloudflare

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Demo stands in for the tunnel in a demo or a test: the same answers and
// the same background job as Service, without Cloudflare, without
// cloudflared and without signing anybody in through it. A token of fewer
// than 20 characters is refused; a hostname that contains "taken" stops at
// a conflict until it is replaced, one that contains "broken" fails at the
// DNS step, so every path of the interface can be tried.
type Demo struct {
	name   string
	bypass []string
	// Step is how long each step of a setup or removal takes.
	Step time.Duration

	mu    sync.Mutex
	st    Status
	logs  *ring
	token bool
	zones []Zone
}

// NewDemo returns a demo tunnel that is not set up yet. name and bypass are
// what Options.Name and Options.Bypass are to a Service.
func NewDemo(name string, bypass []string) *Demo {
	return &Demo{
		name:   name,
		bypass: append([]string(nil), bypass...),
		Step:   600 * time.Millisecond,
		logs:   newRing(200),
		zones: []Zone{
			{ID: "zone-example-com", Name: "example.com", AccountID: "acct-demo", AccountName: "Example"},
			{ID: "zone-example-org", Name: "example.org", AccountID: "acct-demo", AccountName: "Example"},
		},
	}
}

// Seed shows a tunnel that is set up and up, as a demo starts with one.
func (d *Demo) Seed(hostname string, emails []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.token = true
	d.st = d.up(hostname, emails)
}

func (d *Demo) up(host string, emails []string) Status {
	zone := ""
	if i := strings.IndexByte(host, '.'); i >= 0 {
		zone = host[i+1:]
	}
	return Status{Configured: true, Hostname: host, PublicURL: "https://" + host, Emails: append([]string{}, emails...),
		Account: "Example", Zone: zone, Running: true, Connected: true, Verified: true, HasToken: true,
		Cloudflared: Binary{Installed: true, Version: "cloudflared version (demo)", Path: "cloudflared"}}
}

// Status is what the interface shows.
func (d *Demo) Status() Status {
	d.mu.Lock()
	defer d.mu.Unlock()
	st := d.st
	st.Emails = append([]string{}, d.st.Emails...)
	st.Job.Done = append([]string(nil), d.st.Job.Done...)
	st.Job.Conflicts = append([]Conflict(nil), d.st.Job.Conflicts...)
	st.HasToken = d.token
	st.Logs = d.logs.snapshot()
	if !st.Cloudflared.Installed {
		st.Cloudflared = Binary{CanInstall: true}
	}
	return st
}

// TokenURL is Cloudflare's token page.
func (d *Demo) TokenURL() string { return "https://dash.cloudflare.com/profile/api-tokens" }

// BypassPaths are the paths without a login.
func (d *Demo) BypassPaths() []string { return append([]string(nil), d.bypass...) }

// Bypassed reports whether a path is one of the bypass paths.
func (d *Demo) Bypassed(path string) bool {
	for _, p := range d.bypass {
		if path == strings.TrimSuffix(p, "/") || strings.HasPrefix(path, strings.TrimSuffix(p, "/")+"/") {
			return true
		}
	}
	return false
}

func (d *Demo) wait(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d.Step):
		return nil
	}
}

// Check accepts any token of 20 characters or more.
func (d *Demo) Check(ctx context.Context, token string) (TokenInfo, error) {
	if err := d.wait(ctx); err != nil {
		return TokenInfo{}, err
	}
	token = strings.TrimSpace(token)
	d.mu.Lock()
	stored := d.token
	d.mu.Unlock()
	if token == "" && stored {
		return TokenInfo{Zones: d.zones, User: "owner@example.com", Stored: true}, nil
	}
	if len(token) < 20 {
		return TokenInfo{}, errors.New("Cloudflare does not accept this API token: it is too short. Copy all of it and paste it again")
	}
	return TokenInfo{Zones: d.zones, User: "owner@example.com"}, nil
}

// StartSetup runs a pretend setup in the background.
func (d *Demo) StartSetup(req SetupRequest) error {
	host := normHost(req.Hostname)
	emails, err := NormEmails(req.Emails)
	if err != nil {
		return err
	}
	if req.ZoneID == "" || host == "" {
		return errors.New("choose a domain and enter a subdomain")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.st.Job.Running {
		return errors.New("the setup is already running; wait until it is finished")
	}
	if strings.TrimSpace(req.APIToken) == "" && !d.token {
		return errors.New("paste the Cloudflare API token")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	keep := d.st
	d.st.Job = Job{Kind: "setup", Running: true}
	go d.run(ctx, cancel, func(step func(string) error) error {
		steps := []string{
			"Checking the API token and the domain",
			"Checking Cloudflare Zero Trust",
			"Checking " + host,
		}
		for _, s := range steps {
			if err := step(s); err != nil {
				return err
			}
		}
		if strings.Contains(host, "taken") && !req.Replace {
			return &ConflictError{Conflicts: []Conflict{{Kind: "dns", Name: host,
				Detail: fmt.Sprintf("The DNS record %s already exists (A 192.0.2.10) and was not made by %s.", host, d.name)}}}
		}
		for _, s := range []string{"Creating the tunnel", "Routing " + host + " to " + d.name, "Pointing " + host + " at the tunnel"} {
			if err := step(s); err != nil {
				return err
			}
		}
		if strings.Contains(host, "broken") {
			return fmt.Errorf("Cloudflare refused to create the DNS record %s. Choose another subdomain", host)
		}
		for _, s := range []string{"Protecting " + host + " with Cloudflare Access", "Starting cloudflared",
			"Checking from outside that " + host + " asks for a login"} {
			if err := step(s); err != nil {
				return err
			}
		}
		d.mu.Lock()
		d.token = true
		job := d.st.Job
		d.st = d.up(host, emails)
		d.st.Job = job
		d.mu.Unlock()
		return nil
	}, keep)
	return nil
}

// run plays a job's steps and ends it as Service ends one.
func (d *Demo) run(ctx context.Context, cancel context.CancelFunc, body func(step func(string) error) error, before Status) {
	defer cancel()
	step := func(s string) error {
		d.mu.Lock()
		if d.st.Job.Step != "" {
			d.st.Job.Done = append(d.st.Job.Done, d.st.Job.Step)
		}
		d.st.Job.Step = s
		d.logs.add(s)
		d.mu.Unlock()
		return d.wait(ctx)
	}
	err := body(step)
	d.mu.Lock()
	defer d.mu.Unlock()
	d.st.Job.Running = false
	if err == nil {
		if d.st.Job.Step != "" {
			d.st.Job.Done = append(d.st.Job.Done, d.st.Job.Step)
		}
		d.st.Job.Step, d.st.Job.OK = "", true
		return
	}
	job := d.st.Job
	job.Error = err.Error()
	var ce *ConflictError
	if errors.As(err, &ce) {
		job.Conflicts = ce.Conflicts
	}
	d.st = before
	d.st.Job = job
	d.logs.add("failed: " + err.Error())
}

// SetEmails changes who may sign in.
func (d *Demo) SetEmails(ctx context.Context, emails []string) error {
	list, err := NormEmails(emails)
	if err != nil {
		return err
	}
	if err := d.wait(ctx); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.st.Configured {
		return errors.New("set up the tunnel first")
	}
	d.st.Emails = list
	return nil
}

// StartRemove runs a pretend removal in the background.
func (d *Demo) StartRemove() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.st.Job.Running {
		return errors.New("wait until the running job is finished")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	before := d.st
	d.st.Job = Job{Kind: "remove", Running: true}
	go d.run(ctx, cancel, func(step func(string) error) error {
		for _, s := range []string{"Stopping cloudflared", "Deleting the tunnel, its DNS record and the Access applications on Cloudflare", "Forgetting the tunnel"} {
			if err := step(s); err != nil {
				return err
			}
		}
		d.mu.Lock()
		job := d.st.Job
		d.st, d.token = Status{}, false
		d.st.Job = job
		d.mu.Unlock()
		return nil
	}, before)
	return nil
}

// Authenticate refuses everybody: the demo has no tunnel to come through.
func (d *Demo) Authenticate(*http.Request) (string, error) {
	return "", errors.New("the demo has no tunnel")
}

// Allows is false: nobody signs in through the demo's tunnel.
func (d *Demo) Allows(string) bool { return false }

// PublicURL is the pretend address once set up.
func (d *Demo) PublicURL() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.st.PublicURL
}

// Origin is empty: nothing reaches the demo through a tunnel.
func (d *Demo) Origin() string { return "" }

// Run does nothing: there is no cloudflared to supervise.
func (d *Demo) Run(ctx context.Context) { <-ctx.Done() }
