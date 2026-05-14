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

;// ./src/shared/privacy-score.ts
// Score deduction per unique blocked domain in each category.
// Capped at 5× per category so one extremely tracker-heavy site can't
// dominate; the overall picture matters more than raw counts.
const CATEGORY_WEIGHT = {
    'fraud-detection': 10,
    'data-broker': 8,
    'session-replay': 7,
    'social-tracking': 5,
    'behavioral-analytics': 4,
    'marketing-automation': 3,
    'ab-testing': 2,
    'ad-network': 2,
    'telemetry': 1,
};
const CATEGORY_CAP = {
    'fraud-detection': 20,
    'data-broker': 24,
    'session-replay': 21,
    'social-tracking': 20,
    'behavioral-analytics': 16,
    'marketing-automation': 12,
    'ab-testing': 8,
    'ad-network': 18,
    'telemetry': 6,
};
// Score deduction per distinct fingerprint probe type detected.
const PROBE_WEIGHT = {
    audio: 10,
    webgl: 8,
    font: 6,
    hardware: 5,
};
function computePrivacyScore(tab) {
    let totalDeduction = 0;
    const categoryBreakdown = {};
    // Count unique domains per category
    const domainsByCategory = new Map();
    for (const req of tab.blocked) {
        if (!domainsByCategory.has(req.category)) {
            domainsByCategory.set(req.category, new Set());
        }
        domainsByCategory.get(req.category).add(req.domain);
    }
    for (const [cat, domains] of domainsByCategory) {
        const deduction = Math.min(domains.size * CATEGORY_WEIGHT[cat], CATEGORY_CAP[cat]);
        totalDeduction += deduction;
        categoryBreakdown[cat] = domains.size;
    }
    // Fingerprint probe deductions (once per distinct type detected)
    const probesDetected = [...new Set(tab.fingerprintProbes.map((p) => p.type))];
    for (const type of probesDetected) {
        totalDeduction += PROBE_WEIGHT[type];
    }
    const score = Math.max(0, 100 - totalDeduction);
    let label;
    let color;
    if (score >= 85) {
        label = 'Minimal Risk';
        color = '#00d4aa';
    }
    else if (score >= 65) {
        label = 'Low Risk';
        color = '#68d391';
    }
    else if (score >= 40) {
        label = 'Moderate Risk';
        color = '#f6ad55';
    }
    else if (score >= 20) {
        label = 'High Risk';
        color = '#fc8181';
    }
    else {
        label = 'Severe Risk';
        color = '#f56565';
    }
    return { score, label, color, categoryBreakdown, probesDetected };
}

;// ./src/popup/index.ts


function sendMessage(message) {
    return new Promise((resolve) => chrome.runtime.sendMessage(message, resolve));
}
function getCurrentTabId() {
    return new Promise((resolve) => {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => resolve(tabs[0]?.id));
    });
}
// ── Score ring ──────────────────────────────────────────────────────────────
// Circumference of the SVG circle (r=27): 2πr ≈ 169.6
const CIRCUMFERENCE = 2 * Math.PI * 27;
function updateScoreRing(score, color, label) {
    const arc = document.getElementById('score-arc');
    const num = document.getElementById('score-number');
    const lbl = document.getElementById('score-label');
    const offset = CIRCUMFERENCE * (1 - score / 100);
    arc.style.strokeDashoffset = String(offset);
    arc.style.stroke = color;
    num.textContent = String(score);
    num.style.color = color;
    lbl.textContent = label;
    lbl.style.color = color;
}
// ── Category list ───────────────────────────────────────────────────────────
// Category display order — highest severity first
const CATEGORY_ORDER = [
    'fraud-detection',
    'data-broker',
    'session-replay',
    'social-tracking',
    'behavioral-analytics',
    'marketing-automation',
    'ad-network',
    'ab-testing',
    'telemetry',
];
function renderCategoryList(categoryBreakdown) {
    const list = document.getElementById('category-list');
    const clean = document.getElementById('clean-state');
    const categories = CATEGORY_ORDER.filter((c) => (categoryBreakdown[c] ?? 0) > 0);
    // Remove previous rows
    list.querySelectorAll('.category-row').forEach((el) => el.remove());
    if (categories.length === 0) {
        clean.style.display = 'flex';
        return;
    }
    clean.style.display = 'none';
    for (const cat of categories) {
        const meta = CATEGORY_META[cat];
        const count = categoryBreakdown[cat];
        const row = document.createElement('div');
        row.className = 'category-row';
        row.innerHTML = `
      <div class="cat-dot" style="background:${meta.color}"></div>
      <span class="cat-name">${meta.label}</span>
      <span class="cat-count"><strong>${count}</strong> domain${count !== 1 ? 's' : ''}</span>
    `;
        list.appendChild(row);
    }
}
// ── Fingerprint defense grid ────────────────────────────────────────────────
function renderDefenseGrid(canvasSpoofed, webrtcBlocked, enabled, probesDetected) {
    const probeSet = new Set(probesDetected);
    function setDefense(id, state, symbol) {
        const el = document.getElementById(id);
        el.textContent = symbol;
        el.className = `defense-icon ${state}`;
    }
    setDefense('def-canvas', enabled && canvasSpoofed ? 'active' : 'inactive', enabled && canvasSpoofed ? '✓' : '○');
    setDefense('def-webrtc', enabled && webrtcBlocked ? 'active' : 'inactive', enabled && webrtcBlocked ? '✓' : '○');
    setDefense('def-audio', probeSet.has('audio') ? 'detected' : 'active', probeSet.has('audio') ? '⚠' : '✓');
    setDefense('def-webgl', probeSet.has('webgl') ? 'detected' : 'active', probeSet.has('webgl') ? '⚠' : '✓');
    setDefense('def-font', probeSet.has('font') ? 'detected' : 'active', probeSet.has('font') ? '⚠' : '✓');
    setDefense('def-hardware', probeSet.has('hardware') ? 'detected' : 'active', probeSet.has('hardware') ? '⚠' : '✓');
}
// ── Main render ─────────────────────────────────────────────────────────────
async function render() {
    const tabId = await getCurrentTabId();
    const response = await sendMessage({ type: 'GET_STATE' });
    const state = response?.data;
    if (!state)
        return;
    const enabled = state.enabled;
    const tabData = tabId != null
        ? (await sendMessage({ type: 'GET_TAB_DATA', tabId }))?.data ?? null
        : null;
    // Toggle button
    const toggle = document.getElementById('toggle');
    toggle.textContent = enabled ? 'ON' : 'OFF';
    toggle.className = `toggle${enabled ? '' : ' off'}`;
    // Status
    document.getElementById('dot').className = `dot${enabled ? '' : ' off'}`;
    document.getElementById('status-text').textContent = enabled
        ? 'Privacy Intelligence Active'
        : 'Protection Disabled';
    // Score
    const emptyTab = {
        url: '', title: '', blocked: [], fingerprintProbes: [],
        webrtcBlocked: false, canvasSpoofed: false, lastUpdated: 0,
    };
    const tab = enabled ? (tabData ?? emptyTab) : emptyTab;
    const ps = computePrivacyScore(tab);
    if (enabled) {
        updateScoreRing(ps.score, ps.color, ps.label);
    }
    else {
        updateScoreRing(0, '#4a5568', 'Disabled');
    }
    document.getElementById('blocked-count').textContent = String(tab.blocked.length);
    // Threat categories
    renderCategoryList(enabled ? ps.categoryBreakdown : {});
    // Fingerprint defense
    renderDefenseGrid(tab.canvasSpoofed, tab.webrtcBlocked, enabled, enabled ? ps.probesDetected : []);
}
// ── Event listeners ─────────────────────────────────────────────────────────
document.getElementById('toggle').addEventListener('click', async () => {
    await sendMessage({ type: 'TOGGLE_ENABLED' });
    render();
});
document.getElementById('dashboard-btn').addEventListener('click', () => {
    chrome.tabs.create({ url: chrome.runtime.getURL('dashboard.html') });
    window.close();
});
document.getElementById('settings-btn').addEventListener('click', () => {
    chrome.tabs.create({ url: chrome.runtime.getURL('settings.html') });
    window.close();
});
// Live updates while popup is open
chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type === 'BLOCKED' || msg.type === 'PROBE_DETECTED')
        render();
});
render();
setInterval(render, 2000);

/******/ })()
;
//# sourceMappingURL=popup.js.map