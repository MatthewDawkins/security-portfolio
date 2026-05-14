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

;// ./src/shared/tracker-domains.ts
// Domain → threat category map.
// Subdomains are matched automatically — only root domains needed.
// Keep in sync with scripts/generate-rules.js (blocking list).
const TRACKER_MAP = new Map([
    // ── Behavioral Analytics ─────────────────────────────────────────────────
    ['google-analytics.com', 'behavioral-analytics'],
    ['bat.bing.com', 'behavioral-analytics'],
    ['mc.yandex.ru', 'behavioral-analytics'],
    ['mc.yandex.com', 'behavioral-analytics'],
    ['hm.baidu.com', 'behavioral-analytics'],
    ['api.mixpanel.com', 'behavioral-analytics'],
    ['cdn.mixpanel.com', 'behavioral-analytics'],
    ['api.amplitude.com', 'behavioral-analytics'],
    ['cdn.amplitude.com', 'behavioral-analytics'],
    ['analytics.amplitude.com', 'behavioral-analytics'],
    ['cdn.segment.com', 'behavioral-analytics'],
    ['api.segment.io', 'behavioral-analytics'],
    ['cdn.segment.io', 'behavioral-analytics'],
    ['heapanalytics.com', 'behavioral-analytics'],
    ['cdn.heapanalytics.com', 'behavioral-analytics'],
    ['srv.pixel.parsely.com', 'behavioral-analytics'],
    ['pixel.parsely.com', 'behavioral-analytics'],
    ['api.parsely.com', 'behavioral-analytics'],
    ['pendo.io', 'behavioral-analytics'],
    ['cdn.pendo.io', 'behavioral-analytics'],
    // ── Session Replay ────────────────────────────────────────────────────────
    ['hotjar.com', 'session-replay'],
    ['static.hotjar.com', 'session-replay'],
    ['script.hotjar.com', 'session-replay'],
    ['insights.hotjar.com', 'session-replay'],
    ['fullstory.com', 'session-replay'],
    ['rs.fullstory.com', 'session-replay'],
    ['edge.fullstory.com', 'session-replay'],
    ['d.luckyorange.net', 'session-replay'],
    ['cs.luckyorange.net', 'session-replay'],
    ['cdn.mouseflow.com', 'session-replay'],
    ['mouseflow.com', 'session-replay'],
    ['cdn.lr-ingest.io', 'session-replay'],
    ['r.lr-ingest.io', 'session-replay'],
    ['sessioncam.com', 'session-replay'],
    ['clicktale.net', 'session-replay'],
    ['clicktale.com', 'session-replay'],
    ['script.crazyegg.com', 'session-replay'],
    ['clarity.ms', 'session-replay'],
    // ── Social Tracking ───────────────────────────────────────────────────────
    ['connect.facebook.net', 'social-tracking'],
    ['graph.facebook.com', 'social-tracking'],
    ['an.facebook.com', 'social-tracking'],
    ['pixel.facebook.com', 'social-tracking'],
    ['tr.facebook.com', 'social-tracking'],
    ['analytics.twitter.com', 'social-tracking'],
    ['static.ads-twitter.com', 'social-tracking'],
    ['ads.twitter.com', 'social-tracking'],
    ['syndication.twitter.com', 'social-tracking'],
    ['t.co', 'social-tracking'],
    ['snap.licdn.com', 'social-tracking'],
    ['platform.linkedin.com', 'social-tracking'],
    ['ads.linkedin.com', 'social-tracking'],
    ['bizographics.com', 'social-tracking'],
    ['analytics.tiktok.com', 'social-tracking'],
    ['ads-api.tiktok.com', 'social-tracking'],
    ['log.tiktokv.com', 'social-tracking'],
    ['ad.tiktok.com', 'social-tracking'],
    ['tr.snapchat.com', 'social-tracking'],
    ['sc-static.net', 'social-tracking'],
    ['log.pinterest.com', 'social-tracking'],
    ['ct.pinterest.com', 'social-tracking'],
    ['ads.pinterest.com', 'social-tracking'],
    ['trk.pinterest.com', 'social-tracking'],
    ['alb.reddit.com', 'social-tracking'],
    ['pixel.reddit.com', 'social-tracking'],
    ['s7.addthis.com', 'social-tracking'],
    ['m.addthis.com', 'social-tracking'],
    ['addthis.com', 'social-tracking'],
    ['w.sharethis.com', 'social-tracking'],
    ['platform-api.sharethis.com', 'social-tracking'],
    ['a.disquscdn.com', 'social-tracking'],
    ['disqus.com', 'social-tracking'],
    ['disqusads.com', 'social-tracking'],
    // ── Data Broker ───────────────────────────────────────────────────────────
    ['omtrdc.net', 'data-broker'],
    ['demdex.net', 'data-broker'],
    ['adobedtm.com', 'data-broker'],
    ['2o7.net', 'data-broker'],
    ['adobedc.net', 'data-broker'],
    ['omniture.com', 'data-broker'],
    ['tt.omtrdc.net', 'data-broker'],
    ['imrworldwide.com', 'data-broker'],
    ['secure-dcr.imrworldwide.com', 'data-broker'],
    ['cdn-gl.imrworldwide.com', 'data-broker'],
    ['scorecardresearch.com', 'data-broker'],
    ['sb.scorecardresearch.com', 'data-broker'],
    ['pixel.scorecardresearch.com', 'data-broker'],
    ['idsync.rlcdn.com', 'data-broker'],
    ['rlcdn.com', 'data-broker'],
    ['bluekai.com', 'data-broker'],
    ['bkrtx.com', 'data-broker'],
    ['nexac.com', 'data-broker'],
    ['krxd.net', 'data-broker'],
    ['crwdcntrl.net', 'data-broker'],
    ['lotame.com', 'data-broker'],
    ['eyeota.net', 'data-broker'],
    ['bombora.com', 'data-broker'],
    ['dstillery.com', 'data-broker'],
    ['quantserve.com', 'data-broker'],
    ['pixel.quantserve.com', 'data-broker'],
    // ── Marketing Automation ──────────────────────────────────────────────────
    ['js.intercomcdn.com', 'marketing-automation'],
    ['api.intercom.io', 'marketing-automation'],
    ['widget.intercom.io', 'marketing-automation'],
    ['nexus-websocket-a.intercom.io', 'marketing-automation'],
    ['js.hs-analytics.net', 'marketing-automation'],
    ['js.hs-scripts.com', 'marketing-automation'],
    ['track.hubspot.com', 'marketing-automation'],
    ['forms.hsforms.com', 'marketing-automation'],
    ['cta-service-cms2.hubspot.com', 'marketing-automation'],
    ['pi.pardot.com', 'marketing-automation'],
    ['go.pardot.com', 'marketing-automation'],
    ['munchkin.marketo.net', 'marketing-automation'],
    ['app.marketo.com', 'marketing-automation'],
    ['klaviyo.com', 'marketing-automation'],
    ['static.klaviyo.com', 'marketing-automation'],
    ['braze.com', 'marketing-automation'],
    ['appboy.com', 'marketing-automation'],
    ['iad.appboy.com', 'marketing-automation'],
    ['onesignal.com', 'marketing-automation'],
    ['cdn.onesignal.com', 'marketing-automation'],
    ['iterable.com', 'marketing-automation'],
    ['sailthru.com', 'marketing-automation'],
    ['drift.com', 'marketing-automation'],
    ['driftt.com', 'marketing-automation'],
    ['js.driftt.com', 'marketing-automation'],
    ['appcues.com', 'marketing-automation'],
    ['fast.appcues.com', 'marketing-automation'],
    ['walkme.com', 'marketing-automation'],
    ['cdn.walkme.com', 'marketing-automation'],
    // ── A/B Testing ───────────────────────────────────────────────────────────
    ['cdn.optimizely.com', 'ab-testing'],
    ['logx.optimizely.com', 'ab-testing'],
    ['dev.visualwebsiteoptimizer.com', 'ab-testing'],
    ['visualwebsiteoptimizer.com', 'ab-testing'],
    ['siteintercept.qualtrics.com', 'ab-testing'],
    // ── Fraud Detection ───────────────────────────────────────────────────────
    ['threatmetrix.com', 'fraud-detection'],
    ['h.online-metrix.net', 'fraud-detection'],
    ['kount.net', 'fraud-detection'],
    ['sift.com', 'fraud-detection'],
    ['siftscience.com', 'fraud-detection'],
    // ── Telemetry ─────────────────────────────────────────────────────────────
    ['bam.nr-data.net', 'telemetry'],
    ['js-agent.newrelic.com', 'telemetry'],
    ['nr-data.net', 'telemetry'],
    ['static.chartbeat.com', 'telemetry'],
    ['ping.chartbeat.net', 'telemetry'],
    // ── Ad Network ────────────────────────────────────────────────────────────
    ['googletagmanager.com', 'ad-network'],
    ['googletagservices.com', 'ad-network'],
    ['doubleclick.net', 'ad-network'],
    ['googlesyndication.com', 'ad-network'],
    ['googleadservices.com', 'ad-network'],
    ['adservice.google.com', 'ad-network'],
    ['pagead2.googlesyndication.com', 'ad-network'],
    ['stats.g.doubleclick.net', 'ad-network'],
    ['amazon-adsystem.com', 'ad-network'],
    ['aax.amazon-adsystem.com', 'ad-network'],
    ['fls-na.amazon.com', 'ad-network'],
    ['adsystem.amazon.com', 'ad-network'],
    ['ads.microsoft.com', 'ad-network'],
    ['c.bing.com', 'ad-network'],
    ['adnxs.com', 'ad-network'],
    ['ib.adnxs.com', 'ad-network'],
    ['dis.criteo.com', 'ad-network'],
    ['static.criteo.net', 'ad-network'],
    ['gum.criteo.com', 'ad-network'],
    ['sslwidget.criteo.com', 'ad-network'],
    ['bidder.criteo.com', 'ad-network'],
    ['widgets.outbrain.com', 'ad-network'],
    ['log.outbrain.com', 'ad-network'],
    ['amplify.outbrain.com', 'ad-network'],
    ['cdn.taboola.com', 'ad-network'],
    ['trc.taboola.com', 'ad-network'],
    ['log.taboola.com', 'ad-network'],
    ['cdn.doubleverify.com', 'ad-network'],
    ['pub.doubleverify.com', 'ad-network'],
    ['rtb.doubleverify.com', 'ad-network'],
    ['pixel.adsafeprotected.com', 'ad-network'],
    ['fw.adsafeprotected.com', 'ad-network'],
    ['tags.moatads.com', 'ad-network'],
    ['z.moatads.com', 'ad-network'],
    ['match.adsrvr.org', 'ad-network'],
    ['insight.adsrvr.org', 'ad-network'],
    ['adsrvr.org', 'ad-network'],
    ['pixel.mathtag.com', 'ad-network'],
    ['bh.contextweb.com', 'ad-network'],
    ['mathtag.com', 'ad-network'],
    ['ads.pubmatic.com', 'ad-network'],
    ['image.pubmatic.com', 'ad-network'],
    ['simage2.pubmatic.com', 'ad-network'],
    ['us-u.openx.net', 'ad-network'],
    ['openx.net', 'ad-network'],
    ['fastlane.rubiconproject.com', 'ad-network'],
    ['beacon.rubiconproject.com', 'ad-network'],
    ['rubiconproject.com', 'ad-network'],
    ['js-sec.indexww.com', 'ad-network'],
    ['r.casalemedia.com', 'ad-network'],
    ['casalemedia.com', 'ad-network'],
    ['ap.lijit.com', 'ad-network'],
    ['beacon.lijit.com', 'ad-network'],
    ['bidswitch.net', 'ad-network'],
    ['smartadserver.com', 'ad-network'],
    ['sharethrough.com', 'ad-network'],
    ['triplelift.com', 'ad-network'],
    ['3lift.com', 'ad-network'],
    ['sonobi.com', 'ad-network'],
    ['districtm.io', 'ad-network'],
    ['emxdgt.com', 'ad-network'],
    ['33across.com', 'ad-network'],
    ['tynt.com', 'ad-network'],
    ['conversantmedia.com', 'ad-network'],
    ['epsilon.com', 'ad-network'],
    ['adroll.com', 'ad-network'],
    ['d.adroll.com', 'ad-network'],
    ['yieldmo.com', 'ad-network'],
    ['kargo.com', 'ad-network'],
    ['spotx.tv', 'ad-network'],
    ['spotxchange.com', 'ad-network'],
    ['freewheel.tv', 'ad-network'],
    ['adtechfwd.com', 'ad-network'],
    ['teads.tv', 'ad-network'],
    ['teads.com', 'ad-network'],
    ['nativo.com', 'ad-network'],
    ['postrelease.com', 'ad-network'],
    ['serving-sys.com', 'ad-network'],
    ['exponential.com', 'ad-network'],
    ['tribalfusion.com', 'ad-network'],
    ['valueclick.com', 'ad-network'],
    ['fastclick.net', 'ad-network'],
    ['undertone.com', 'ad-network'],
    ['gumgum.com', 'ad-network'],
    ['liadm.com', 'ad-network'],
    ['liveintent.com', 'ad-network'],
    ['adform.net', 'ad-network'],
    ['track.adform.net', 'ad-network'],
    ['media.net', 'ad-network'],
    ['advertising.yahoo.com', 'ad-network'],
    ['amobee.com', 'ad-network'],
    ['turn.com', 'ad-network'],
    ['pulsepoint.com', 'ad-network'],
    ['contextweb.com', 'ad-network'],
    ['xaxis.com', 'ad-network'],
    ['dataxu.com', 'ad-network'],
]);
/**
 * Returns the threat category for a given hostname, or null if not a known tracker.
 * Walks up subdomains: "foo.bar.doubleclick.net" → checks "bar.doubleclick.net", "doubleclick.net".
 */
function getTrackerCategory(hostname) {
    if (TRACKER_MAP.has(hostname))
        return TRACKER_MAP.get(hostname);
    const parts = hostname.split('.');
    for (let i = 1; i < parts.length - 1; i++) {
        const parent = parts.slice(i).join('.');
        if (TRACKER_MAP.has(parent))
            return TRACKER_MAP.get(parent);
    }
    return null;
}
/** Returns true if the hostname is a known tracker domain. */
function isTrackerDomain(hostname) {
    return getTrackerCategory(hostname) !== null;
}

;// ./src/background/index.ts
// MV3 Service Worker background.
// declarativeNetRequest handles tracker blocking (rules.json).
// chrome.scripting dynamically registers MAIN-world scripts — both defenses
// (canvas spoofing, WebRTC relay-only) and detectors (audio, webgl, fonts, hardware).


// ── Storage helpers ────────────────────────────────────────────────────────
async function loadState() {
    return new Promise((resolve) => {
        chrome.storage.local.get(['enabled', 'totalBlocked', 'tabs'], (result) => {
            resolve({
                enabled: result.enabled !== false,
                totalBlocked: result.totalBlocked || 0,
                tabs: result.tabs || {},
            });
        });
    });
}
async function saveState(state) {
    return new Promise((resolve) => {
        chrome.storage.local.set({ enabled: state.enabled, totalBlocked: state.totalBlocked, tabs: state.tabs }, resolve);
    });
}
async function loadSettings() {
    return new Promise((resolve) => {
        chrome.storage.local.get(['settings'], (result) => {
            resolve({ ...DEFAULT_SETTINGS, ...(result.settings ?? {}) });
        });
    });
}
async function saveSettings(settings) {
    return new Promise((resolve) => {
        chrome.storage.local.set({ settings }, resolve);
    });
}
// ── Content script IDs ────────────────────────────────────────────────────
// Defenses run in MAIN world to bypass CSP and intercept APIs before page scripts.
// Detectors also run in MAIN world to intercept API calls and fire CustomEvents
// that content.js (isolated world) listens for and forwards to background.
const SCRIPT_IDS = {
    canvas: 'eidolon-canvas',
    webrtc: 'eidolon-webrtc',
    audio: 'eidolon-audio',
    webgl: 'eidolon-webgl',
    fonts: 'eidolon-fonts',
    hardware: 'eidolon-hardware',
};
async function syncContentScripts(enabled, settings) {
    const registered = await chrome.scripting.getRegisteredContentScripts();
    const activeIds = new Set(registered.map((s) => s.id));
    const desired = {
        canvas: enabled && settings.spoofCanvas,
        webrtc: enabled && settings.blockWebRTC,
        audio: enabled && settings.detectAudioFingerprint,
        webgl: enabled && settings.detectWebGLFingerprint,
        fonts: enabled && settings.detectFontEnumeration,
        hardware: enabled && settings.detectHardwareProbe,
    };
    const toRegister = [];
    const toUnregister = [];
    for (const [key, want] of Object.entries(desired)) {
        const id = SCRIPT_IDS[key];
        if (want && !activeIds.has(id)) {
            toRegister.push({
                id,
                matches: ['<all_urls>'],
                js: [`${key}.js`],
                runAt: 'document_start',
                world: 'MAIN',
                allFrames: true,
            });
        }
        else if (!want && activeIds.has(id)) {
            toUnregister.push(id);
        }
    }
    if (toRegister.length)
        await chrome.scripting.registerContentScripts(toRegister);
    if (toUnregister.length)
        await chrome.scripting.unregisterContentScripts({ ids: toUnregister });
}
async function syncRulesets(enabled, settings) {
    const shouldBlock = enabled && settings.blockTrackers;
    await chrome.declarativeNetRequest.updateEnabledRulesets(shouldBlock
        ? { enableRulesetIds: ['tracker-rules'], disableRulesetIds: [] }
        : { enableRulesetIds: [], disableRulesetIds: ['tracker-rules'] });
}
// ── Initialisation ────────────────────────────────────────────────────────
chrome.runtime.onInstalled.addListener(async () => {
    const [state, settings] = await Promise.all([loadState(), loadSettings()]);
    await Promise.all([syncContentScripts(state.enabled, settings), syncRulesets(state.enabled, settings)]);
});
// ── webRequest observer ────────────────────────────────────────────────────
// Observes requests to classify and record blocked trackers per tab.
// The actual network block is handled by declarativeNetRequest (rules.json).
chrome.webRequest.onBeforeRequest.addListener((details) => {
    if (details.tabId < 0)
        return;
    let hostname;
    try {
        hostname = new URL(details.url).hostname.replace(/^www\./, '');
    }
    catch {
        return;
    }
    if (!isTrackerDomain(hostname))
        return;
    recordBlock(details.tabId, details.url, details.type, hostname);
}, { urls: ['<all_urls>'] });
async function recordBlock(tabId, url, type, domain) {
    const state = await loadState();
    if (!state.enabled)
        return;
    const category = getTrackerCategory(domain) ?? 'ad-network';
    if (!state.tabs[tabId]) {
        state.tabs[tabId] = emptyTabData();
    }
    const blocked = { url, type, reason: 'tracker', timestamp: Date.now(), domain, category };
    state.tabs[tabId].blocked.push(blocked);
    state.tabs[tabId].lastUpdated = Date.now();
    state.totalBlocked++;
    await saveState(state);
    chrome.runtime.sendMessage({ type: 'BLOCKED', tabId, blocked }).catch(() => { });
}
// ── Fingerprint probe recording ───────────────────────────────────────────
async function recordProbe(tabId, probe) {
    const state = await loadState();
    if (!state.enabled)
        return;
    if (!state.tabs[tabId]) {
        state.tabs[tabId] = emptyTabData();
    }
    // Deduplicate: only store the first occurrence of each probe type per tab
    const existing = state.tabs[tabId].fingerprintProbes;
    if (!existing.some((p) => p.type === probe.type)) {
        existing.push(probe);
        state.tabs[tabId].lastUpdated = Date.now();
        await saveState(state);
        chrome.runtime.sendMessage({ type: 'PROBE_DETECTED', tabId, probe }).catch(() => { });
    }
}
// ── Tab lifecycle ──────────────────────────────────────────────────────────
function emptyTabData() {
    return {
        url: '', title: '', blocked: [], fingerprintProbes: [],
        webrtcBlocked: false, canvasSpoofed: false, lastUpdated: Date.now(),
    };
}
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    if (changeInfo.status === 'loading' && changeInfo.url) {
        const state = await loadState();
        state.tabs[tabId] = { ...emptyTabData(), url: changeInfo.url };
        await saveState(state);
        return;
    }
    if (changeInfo.url || changeInfo.title) {
        const state = await loadState();
        if (state.tabs[tabId]) {
            if (changeInfo.url)
                state.tabs[tabId].url = changeInfo.url;
            if (tab.title)
                state.tabs[tabId].title = tab.title;
            await saveState(state);
        }
    }
});
chrome.tabs.onRemoved.addListener(async (tabId) => {
    const state = await loadState();
    delete state.tabs[tabId];
    await saveState(state);
});
// ── Message handling ───────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    handleMessage(message, sender).then(sendResponse).catch(() => sendResponse(null));
    return true;
});
async function handleMessage(message, sender) {
    const state = await loadState();
    switch (message.type) {
        case 'GET_STATE':
            return { data: state };
        case 'GET_TAB_DATA':
            return { data: state.tabs[message.tabId] ?? null };
        case 'TOGGLE_ENABLED': {
            state.enabled = !state.enabled;
            await saveState(state);
            const settings = await loadSettings();
            await Promise.all([syncContentScripts(state.enabled, settings), syncRulesets(state.enabled, settings)]);
            return { enabled: state.enabled };
        }
        case 'GET_SETTINGS':
            return { data: await loadSettings() };
        case 'SAVE_SETTINGS': {
            const newSettings = message.settings;
            await saveSettings(newSettings);
            await Promise.all([syncContentScripts(state.enabled, newSettings), syncRulesets(state.enabled, newSettings)]);
            return { ok: true };
        }
        case 'CANVAS_SPOOFED':
            if (sender.tab?.id != null) {
                if (!state.tabs[sender.tab.id])
                    state.tabs[sender.tab.id] = emptyTabData();
                state.tabs[sender.tab.id].canvasSpoofed = true;
                await saveState(state);
            }
            return null;
        case 'WEBRTC_BLOCKED':
            if (sender.tab?.id != null) {
                if (!state.tabs[sender.tab.id])
                    state.tabs[sender.tab.id] = emptyTabData();
                state.tabs[sender.tab.id].webrtcBlocked = true;
                await saveState(state);
            }
            return null;
        case 'FINGERPRINT_PROBE':
            if (sender.tab?.id != null && message.probe) {
                await recordProbe(sender.tab.id, message.probe);
            }
            return null;
        case 'OPEN_DASHBOARD':
            chrome.tabs.create({ url: chrome.runtime.getURL('dashboard.html') });
            return null;
        default:
            return null;
    }
}

/******/ })()
;
//# sourceMappingURL=background.js.map