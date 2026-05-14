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

;// ./src/settings/index.ts

function sendMessage(message) {
    return new Promise((resolve) => chrome.runtime.sendMessage(message, resolve));
}
const SETTING_IDS = [
    'blockTrackers',
    'spoofCanvas',
    'blockWebRTC',
    'detectAudioFingerprint',
    'detectWebGLFingerprint',
    'detectFontEnumeration',
    'detectHardwareProbe',
];
async function load() {
    const response = await sendMessage({ type: 'GET_SETTINGS' });
    const settings = { ...DEFAULT_SETTINGS, ...(response?.data ?? {}) };
    for (const id of SETTING_IDS) {
        const el = document.getElementById(id);
        if (el)
            el.checked = settings[id];
    }
}
async function save() {
    const settings = {};
    for (const id of SETTING_IDS) {
        const el = document.getElementById(id);
        if (el)
            settings[id] = el.checked;
    }
    await sendMessage({ type: 'SAVE_SETTINGS', settings: { ...DEFAULT_SETTINGS, ...settings } });
    const bar = document.getElementById('status-bar');
    bar.classList.remove('saving');
    void bar.offsetWidth;
    bar.classList.add('saving');
}
for (const id of SETTING_IDS) {
    document.getElementById(id)?.addEventListener('change', save);
}
document.getElementById('reload-btn').addEventListener('click', () => {
    chrome.tabs.query({}, (tabs) => {
        for (const tab of tabs) {
            if (tab.id != null && !tab.url?.startsWith('chrome://') && !tab.url?.startsWith('chrome-extension://')) {
                chrome.tabs.reload(tab.id);
            }
        }
    });
});
load();

/******/ })()
;
//# sourceMappingURL=settings.js.map