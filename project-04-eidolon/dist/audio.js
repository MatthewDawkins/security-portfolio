/******/ (() => { // webpackBootstrap
/******/ 	"use strict";

// AudioContext fingerprint detector — injected into MAIN world.
// No chrome.* APIs available here. Communicates detections via CustomEvent
// which content.js (isolated world) listens for and forwards to background.
//
// Detection: OfflineAudioContext.startRendering() is the canonical audio
// fingerprinting API. Pages create an offline context, run an oscillator
// through a compressor, render it, and read the resulting buffer to get
// a hardware-specific floating-point signature.
if (typeof OfflineAudioContext !== 'undefined') {
    const orig = OfflineAudioContext.prototype.startRendering;
    OfflineAudioContext.prototype.startRendering = function () {
        window.dispatchEvent(new CustomEvent('eidolon-probe', {
            detail: {
                type: 'audio',
                detail: 'OfflineAudioContext.startRendering() called — audio fingerprinting probe detected. ' +
                    'This API is used to extract hardware-specific floating-point rendering characteristics.',
            },
        }));
        return orig.call(this);
    };
}

/******/ })()
;
//# sourceMappingURL=audio.js.map