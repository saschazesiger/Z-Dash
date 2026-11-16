/**
 * DS.lightbox without a DOM: its registration, the zoom steps, a tall image
 * and the pan clamp. The behaviour in a browser is lightbox.spec.js.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import * as lightbox from './lightbox.js';
import { runtime, t } from '../../js/core.js';

describe('DS.lightbox', () => {
  it('registers its behaviour by its attribute', () => {
    const spec = runtime.state('core').specs.get('lightbox');
    assert.equal(spec.attribute, 'data-ds-lightbox');
    assert.equal(typeof spec.init, 'function');
  });

  it('steps the zoom 1, 2, 4 and back, never past its ends', () => {
    assert.equal(lightbox.nextZoom(1, 1), 2);
    assert.equal(lightbox.nextZoom(2, 1), 4);
    assert.equal(lightbox.nextZoom(4, 1), lightbox.MAX_ZOOM);
    assert.equal(lightbox.nextZoom(4, -1), 2);
    assert.equal(lightbox.nextZoom(1, -1), 1);
    assert.equal(lightbox.nextZoom(3, 0), 1);
    assert.equal(lightbox.nextZoom(1.5, 1), 3);
  });

  it('zooms a click to the image\'s own pixels, at least 2 and at most MAX_ZOOM', () => {
    assert.equal(lightbox.detailZoom(1600, 500), 3.2);
    assert.equal(lightbox.detailZoom(3840, 400), lightbox.MAX_ZOOM);
    // Shown at its own size (or larger): still twice as close.
    assert.equal(lightbox.detailZoom(400, 400), 2);
    assert.equal(lightbox.detailZoom(200, 400), 2);
    // Not loaded yet, or not laid out: the plain step.
    assert.equal(lightbox.detailZoom(0, 400), 2);
    assert.equal(lightbox.detailZoom(1600, 0), 2);
  });

  it('calls an image tall from TALL_RATIO times as high as wide', () => {
    assert.equal(lightbox.TALL_RATIO, 2);
    // A full-page screenshot and a phone's.
    assert.equal(lightbox.isTall(1280, 6000), true);
    assert.equal(lightbox.isTall(1170, 2532), true);
    assert.equal(lightbox.isTall(1000, 2000), true);
    // A portrait photo fits whole; a landscape one too.
    assert.equal(lightbox.isTall(3000, 4000), false);
    assert.equal(lightbox.isTall(1600, 900), false);
    // Not loaded yet.
    assert.equal(lightbox.isTall(0, 0), false);
  });

  it('keeps a zoomed image covering its frame, and an unzoomed one still', () => {
    const frame = { width: 800, height: 600 };
    const size = { width: 800, height: 450 };
    // Fitted: nothing to pan.
    assert.deepEqual(lightbox.clampPan(120, -40, size, frame, 1), { x: 0, y: 0 });
    // At 2: 1600 wide, 400px of reach each way; 900 high, 150 each way.
    assert.deepEqual(lightbox.clampPan(500, -200, size, frame, 2), { x: 400, y: -150 });
    assert.deepEqual(lightbox.clampPan(-120.4, 60.6, size, frame, 2), { x: -120, y: 61 });
    // A narrow image at 2 is still narrower than the frame: no sideways pan.
    assert.deepEqual(lightbox.clampPan(90, 0, { width: 300, height: 600 }, frame, 2), { x: 0, y: 0 });
    // A tall image at the fit: as wide as the frame, 2000 high, 700px of reach up and down and none sideways.
    assert.deepEqual(lightbox.clampPan(50, 5000, { width: 800, height: 2000 }, frame, 1), { x: 0, y: 700 });
  });

  it('says where the viewer is in the system\'s words', () => {
    assert.equal(t('imageOf', { index: 3, total: 6 }), 'Image 3 of 6');
    assert.equal(t('zoomIn'), 'Zoom in');
    assert.equal(t('openImage'), 'Open the image');
  });
});
