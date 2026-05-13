/******/ (() => { // webpackBootstrap
/******/ 	"use strict";

// Canvas fingerprint spoofer — injected into MAIN world via dynamic content script registration.
// No chrome.* APIs available. Registered/unregistered by the background based on settings.
const SESSION_SEED = (Math.random() * 0x7fffffff) | 0;
function noise(input) {
    let s = ((input ^ SESSION_SEED) * 1664525 + 1013904223) | 0;
    return (s >>> 0) / 0x100000000;
}
const _toDataURL = HTMLCanvasElement.prototype.toDataURL;
HTMLCanvasElement.prototype.toDataURL = function (type, quality) {
    if (this.width === 0 || this.height === 0)
        return _toDataURL.call(this, type, quality);
    const off = document.createElement('canvas');
    off.width = this.width;
    off.height = this.height;
    const ctx = off.getContext('2d');
    if (!ctx)
        return _toDataURL.call(this, type, quality);
    ctx.drawImage(this, 0, 0);
    const img = ctx.getImageData(0, 0, off.width, off.height);
    const total = off.width * off.height;
    for (let i = 0; i < 8; i++) {
        const px = Math.floor(noise(i) * total) * 4;
        if (px + 2 < img.data.length) {
            const delta = Math.floor(noise(i + 50) * 3) - 1;
            img.data[px] = Math.max(0, Math.min(255, img.data[px] + delta));
        }
    }
    ctx.putImageData(img, 0, 0);
    return _toDataURL.call(off, type, quality);
};
const _getImageData = CanvasRenderingContext2D.prototype.getImageData;
CanvasRenderingContext2D.prototype.getImageData = function (sx, sy, sw, sh) {
    const img = _getImageData.call(this, sx, sy, sw, sh);
    const total = sw * sh;
    for (let i = 0; i < 4; i++) {
        const px = Math.floor(noise(i + 100) * total) * 4;
        if (px + 2 < img.data.length) {
            const delta = Math.floor(noise(i + 150) * 3) - 1;
            img.data[px] = Math.max(0, Math.min(255, img.data[px] + delta));
        }
    }
    return img;
};

/******/ })()
;
//# sourceMappingURL=canvas.js.map