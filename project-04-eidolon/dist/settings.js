/******/ (() => { // webpackBootstrap
/******/ 	"use strict";

;// ./src/shared/types.ts
const DEFAULT_SETTINGS = {
    blockTrackers: true,
    spoofCanvas: true,
    blockWebRTC: true,
};

;// ./src/settings/index.ts

function sendMessage(message) {
    return new Promise((resolve) => chrome.runtime.sendMessage(message, resolve));
}
async function load() {
    const response = await sendMessage({ type: 'GET_SETTINGS' });
    const settings = response?.data ?? { ...DEFAULT_SETTINGS };
    document.getElementById('blockTrackers').checked = settings.blockTrackers;
    document.getElementById('spoofCanvas').checked = settings.spoofCanvas;
    document.getElementById('blockWebRTC').checked = settings.blockWebRTC;
}
async function save() {
    const settings = {
        blockTrackers: document.getElementById('blockTrackers').checked,
        spoofCanvas: document.getElementById('spoofCanvas').checked,
        blockWebRTC: document.getElementById('blockWebRTC').checked,
    };
    await sendMessage({ type: 'SAVE_SETTINGS', settings });
    // Brief visual confirmation
    const bar = document.getElementById('status-bar');
    bar.classList.remove('saving');
    void bar.offsetWidth; // force reflow to restart animation
    bar.classList.add('saving');
}
document.getElementById('blockTrackers').addEventListener('change', save);
document.getElementById('spoofCanvas').addEventListener('change', save);
document.getElementById('blockWebRTC').addEventListener('change', save);
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