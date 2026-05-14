/******/ (() => { // webpackBootstrap
/******/ 	"use strict";

;// ./src/shared/types.ts
// ── Threat taxonomy ─────────────────────────────────────────────────────────
const CATEGORY_META = {
    'fraud-detection': {
        label: 'Fraud Detection',
        description: 'Device fingerprinting systems that build persistent identity tokens from hardware characteristics. Functionally indistinguishable from surveillance infrastructure.',
        severity: 'critical',
        color: '#f56565',
    },
    'data-broker': {
        label: 'Data Broker',
        description: 'Data management platforms and identity resolution networks that aggregate your browsing activity across thousands of sites to build and sell behavioral profiles.',
        severity: 'high',
        color: '#fc8181',
    },
    'session-replay': {
        label: 'Session Replay',
        description: 'Tools that record every mouse movement, click, scroll, and keystroke — reconstructing exact video replays of your browsing session.',
        severity: 'high',
        color: '#f6ad55',
    },
    'social-tracking': {
        label: 'Social Tracking',
        description: 'Social media pixels that correlate your activity across sites with your social network identity, enabling cross-site behavioral attribution.',
        severity: 'high',
        color: '#ed8936',
    },
    'behavioral-analytics': {
        label: 'Behavioral Analytics',
        description: 'Product analytics platforms that track every user action, event, and conversion funnel step to build detailed behavioral engagement profiles.',
        severity: 'medium',
        color: '#68d391',
    },
    'marketing-automation': {
        label: 'Marketing Automation',
        description: 'CRM and email marketing systems that tie your web activity to your email address for targeted outreach, lead scoring, and conversion tracking.',
        severity: 'medium',
        color: '#63b3ed',
    },
    'ab-testing': {
        label: 'A/B Testing',
        description: 'Experimentation and optimization platforms that track which content variants you see and measure behavioral responses to influence product decisions.',
        severity: 'low',
        color: '#76e4f7',
    },
    'ad-network': {
        label: 'Ad Network',
        description: 'Programmatic advertising infrastructure — DSPs, SSPs, ad exchanges, and verification layers — that bid on your attention in real-time auctions.',
        severity: 'medium',
        color: '#b794f4',
    },
    'telemetry': {
        label: 'Telemetry',
        description: 'Performance monitoring and audience measurement systems collecting page metrics, engagement signals, and audience statistics.',
        severity: 'low',
        color: '#90cdf4',
    },
};
const DEFAULT_SETTINGS = {
    blockTrackers: true,
    spoofCanvas: true,
    blockWebRTC: true,
    detectAudioFingerprint: true,
    detectWebGLFingerprint: true,
    detectFontEnumeration: true,
    detectHardwareProbe: true,
};

;// ./src/content/index.ts
// Content script — isolated world, document_start.
// Forwards status notifications from MAIN-world scripts to the background:
//   - canvas.js / webrtc.js call chrome.runtime.sendMessage directly (N/A from MAIN world)
//     so we use this script to send them after reading storage.
//   - audio.js / webgl.js / fonts.js / hardware.js fire CustomEvents on window
//     which this script listens for and forwards as FINGERPRINT_PROBE messages.

chrome.storage.local.get(['enabled', 'settings'], (result) => {
    const enabled = result.enabled !== false;
    if (!enabled)
        return;
    const settings = { ...DEFAULT_SETTINGS, ...(result.settings ?? {}) };
    // Notify background that defenses are active on this tab
    if (settings.spoofCanvas)
        chrome.runtime.sendMessage({ type: 'CANVAS_SPOOFED' }).catch(() => { });
    if (settings.blockWebRTC)
        chrome.runtime.sendMessage({ type: 'WEBRTC_BLOCKED' }).catch(() => { });
});
// Forward fingerprint probe detections from MAIN-world detector scripts.
// The CustomEvent 'eidolon-probe' is dispatched by audio.js, webgl.js, fonts.js, hardware.js.
window.addEventListener('eidolon-probe', (e) => {
    const { detail } = e;
    if (!detail?.type)
        return;
    const probe = {
        type: detail.type,
        detail: detail.detail,
        timestamp: Date.now(),
    };
    chrome.runtime.sendMessage({ type: 'FINGERPRINT_PROBE', probe }).catch(() => { });
});

/******/ })()
;
//# sourceMappingURL=content.js.map