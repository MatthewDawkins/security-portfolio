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

;// ./src/dashboard/index.ts


function sendMessage(message) {
    return new Promise((resolve) => chrome.runtime.sendMessage(message, resolve));
}
function timeAgo(ts) {
    const s = Math.floor((Date.now() - ts) / 1000);
    if (s < 60)
        return `${s}s ago`;
    if (s < 3600)
        return `${Math.floor(s / 60)}m ago`;
    return `${Math.floor(s / 3600)}h ago`;
}
function domainOf(url) {
    try {
        return new URL(url).hostname.replace(/^www\./, '');
    }
    catch {
        return url;
    }
}
// ── Category chips ──────────────────────────────────────────────────────────
function buildCategoryChips(breakdown) {
    return Object.entries(breakdown)
        .map(([cat, count]) => {
        const meta = CATEGORY_META[cat];
        return `<div class="cat-chip">
        <div class="cat-chip-dot" style="background:${meta.color}"></div>
        ${meta.label} <strong style="color:#e2e8f0;margin-left:2px">${count}</strong>
      </div>`;
    })
        .join('');
}
// ── Probe chips ─────────────────────────────────────────────────────────────
const PROBE_LABELS = {
    audio: 'Audio FP',
    webgl: 'WebGL FP',
    font: 'Font Enum',
    hardware: 'Hardware Profile',
};
function buildProbeChips(probes) {
    if (probes.length === 0)
        return '';
    const types = [...new Set(probes.map((p) => p.type))];
    return types.map((t) => `<div class="probe-chip">⚠ ${PROBE_LABELS[t] ?? t}</div>`).join('');
}
function buildProbeDetails(probes) {
    if (probes.length === 0)
        return '';
    return probes.map((p) => `<div class="probe-detail-row">${p.detail}</div>`).join('');
}
// ── Request table ───────────────────────────────────────────────────────────
function buildRequestTable(blocked) {
    if (blocked.length === 0) {
        return '<div style="padding:10px 14px;color:#4a5568;font-size:10px">No requests blocked on this page.</div>';
    }
    const rows = [...blocked]
        .reverse()
        .map((r) => {
        const meta = CATEGORY_META[r.category];
        return `<div class="request-row">
        <span class="req-domain" title="${r.url}">${r.domain}</span>
        <span class="req-type">${r.type}</span>
        <span class="req-cat" style="color:${meta.color}">${meta.label}</span>
        <span class="req-time">${timeAgo(r.timestamp)}</span>
      </div>`;
    })
        .join('');
    return `
    <div class="request-row hdr">
      <span>Domain</span>
      <span>Type</span>
      <span>Category</span>
      <span style="text-align:right">Time</span>
    </div>
    ${rows}
  `;
}
// ── Tab card ────────────────────────────────────────────────────────────────
function buildTabCard(tabId, data) {
    const ps = computePrivacyScore(data);
    const title = data.title || domainOf(data.url) || `Tab ${tabId}`;
    const blockCount = data.blocked.length;
    const probeCount = data.fingerprintProbes.length;
    const hasCats = Object.keys(ps.categoryBreakdown).length > 0;
    const card = document.createElement('div');
    card.className = 'tab-card';
    const probeWarning = probeCount > 0
        ? `<div class="badge warn">⚠ ${probeCount} FP probe${probeCount !== 1 ? 's' : ''}</div>`
        : '';
    const blockBadge = blockCount > 0
        ? `<div class="badge">${blockCount} blocked</div>`
        : `<div class="badge zero">0 blocked</div>`;
    card.innerHTML = `
    <div class="tab-header">
      <div class="tab-score" style="color:${ps.color};border-color:${ps.color}33">
        ${ps.score}
      </div>
      <div class="tab-info">
        <div class="tab-title">${title}</div>
        <div class="tab-url">${domainOf(data.url)}</div>
      </div>
      <div class="tab-badges">
        ${probeWarning}
        ${blockBadge}
        ${data.canvasSpoofed ? '<div class="badge green">canvas ✓</div>' : ''}
        ${data.webrtcBlocked ? '<div class="badge green">webrtc ✓</div>' : ''}
      </div>
      <span class="chevron">&#9658;</span>
    </div>
    <div class="tab-detail">
      ${hasCats ? `<div class="card-categories">${buildCategoryChips(ps.categoryBreakdown)}</div>` : ''}
      ${probeCount > 0 ? `
        <div class="card-probes">${buildProbeChips(data.fingerprintProbes)}</div>
        ${buildProbeDetails(data.fingerprintProbes)}
      ` : ''}
      <div class="request-table">${buildRequestTable(data.blocked)}</div>
    </div>
  `;
    card.querySelector('.tab-header').addEventListener('click', () => card.classList.toggle('open'));
    return card;
}
// ── Main render ─────────────────────────────────────────────────────────────
async function render() {
    const response = await sendMessage({ type: 'GET_STATE' });
    const state = response?.data;
    if (!state)
        return;
    const entries = Object.entries(state.tabs);
    // Summary tiles
    document.getElementById('total-blocked').textContent = String(state.totalBlocked);
    document.getElementById('tabs-active').textContent = String(entries.length);
    const totalProbes = entries.reduce((sum, [, tab]) => sum + tab.fingerprintProbes.length, 0);
    document.getElementById('total-probes').textContent = String(totalProbes);
    const container = document.getElementById('tabs-container');
    container.innerHTML = '';
    if (entries.length === 0) {
        container.innerHTML = `
      <div class="empty-tabs">
        <p>No tab data yet.</p>
        <small>Browse a few pages and come back.</small>
      </div>
    `;
        return;
    }
    // Sort: highest threat first (lowest score first), then most blocked
    entries.sort(([, a], [, b]) => {
        const sa = computePrivacyScore(a).score;
        const sb = computePrivacyScore(b).score;
        if (sa !== sb)
            return sa - sb;
        return b.blocked.length - a.blocked.length;
    });
    for (const [tabId, data] of entries) {
        container.appendChild(buildTabCard(tabId, data));
    }
}
document.getElementById('refresh-btn').addEventListener('click', render);
render();
setInterval(render, 3000);

/******/ })()
;
//# sourceMappingURL=dashboard.js.map