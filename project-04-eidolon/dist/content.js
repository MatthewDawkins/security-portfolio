/******/ (() => { // webpackBootstrap
/******/ 	"use strict";

;// ./src/shared/types.ts
const DEFAULT_SETTINGS = {
    blockTrackers: true,
    spoofCanvas: true,
    blockWebRTC: true,
};

;// ./src/content/index.ts
// Content script — isolated world, document_start.
// canvas.js and webrtc.js are injected by the background via chrome.scripting
// (MAIN world, bypasses CSP). This script just notifies the background that
// the protections are active on this tab so the popup/dashboard can show stats.

chrome.storage.local.get(['enabled', 'settings'], (result) => {
    const enabled = result.enabled !== false;
    if (!enabled)
        return;
    const settings = { ...DEFAULT_SETTINGS, ...(result.settings ?? {}) };
    if (settings.spoofCanvas)
        chrome.runtime.sendMessage({ type: 'CANVAS_SPOOFED' }).catch(() => { });
    if (settings.blockWebRTC)
        chrome.runtime.sendMessage({ type: 'WEBRTC_BLOCKED' }).catch(() => { });
});

/******/ })()
;
//# sourceMappingURL=content.js.map