/******/ (() => { // webpackBootstrap
/******/ 	"use strict";

;// ./src/shared/types.ts
const DEFAULT_SETTINGS = {
    blockTrackers: true,
    spoofCanvas: true,
    blockWebRTC: true,
};

;// ./src/shared/tracker-domains.ts
// Curated list of known tracker/ad domains.
// Subdomains are matched automatically — only root domains needed here.
const TRACKER_DOMAINS = new Set([
    // Google Analytics & Ads
    'google-analytics.com',
    'googletagmanager.com',
    'googletagservices.com',
    'doubleclick.net',
    'googlesyndication.com',
    'googleadservices.com',
    'adservice.google.com',
    'pagead2.googlesyndication.com',
    'stats.g.doubleclick.net',
    // Facebook / Meta
    'connect.facebook.net',
    'graph.facebook.com',
    'an.facebook.com',
    'pixel.facebook.com',
    'tr.facebook.com',
    // Twitter / X
    'analytics.twitter.com',
    'static.ads-twitter.com',
    'ads.twitter.com',
    'syndication.twitter.com',
    't.co',
    // LinkedIn
    'snap.licdn.com',
    'platform.linkedin.com',
    'ads.linkedin.com',
    'bizographics.com',
    // Amazon Ads
    'amazon-adsystem.com',
    'aax.amazon-adsystem.com',
    'fls-na.amazon.com',
    'adsystem.amazon.com',
    // Microsoft / Bing
    'bat.bing.com',
    'clarity.ms',
    'ads.microsoft.com',
    'c.bing.com',
    // Adobe Analytics / Marketing Cloud
    'omtrdc.net',
    'demdex.net',
    'adobedtm.com',
    '2o7.net',
    'adobedc.net',
    'omniture.com',
    'tt.omtrdc.net',
    // Hotjar
    'hotjar.com',
    'static.hotjar.com',
    'script.hotjar.com',
    'insights.hotjar.com',
    // Mixpanel
    'api.mixpanel.com',
    'cdn.mixpanel.com',
    // Amplitude
    'api.amplitude.com',
    'cdn.amplitude.com',
    'analytics.amplitude.com',
    // Segment
    'cdn.segment.com',
    'api.segment.io',
    'cdn.segment.io',
    // Heap
    'heapanalytics.com',
    'cdn.heapanalytics.com',
    // FullStory
    'fullstory.com',
    'rs.fullstory.com',
    'edge.fullstory.com',
    // Intercom
    'js.intercomcdn.com',
    'api.intercom.io',
    'widget.intercom.io',
    'nexus-websocket-a.intercom.io',
    // HubSpot
    'js.hs-analytics.net',
    'js.hs-scripts.com',
    'track.hubspot.com',
    'forms.hsforms.com',
    'cta-service-cms2.hubspot.com',
    // Pardot / Salesforce
    'pi.pardot.com',
    'go.pardot.com',
    // Marketo
    'munchkin.marketo.net',
    'app.marketo.com',
    // Quantcast
    'quantserve.com',
    'pixel.quantserve.com',
    // AppNexus / Xandr
    'adnxs.com',
    'ib.adnxs.com',
    // Criteo
    'dis.criteo.com',
    'static.criteo.net',
    'gum.criteo.com',
    'sslwidget.criteo.com',
    'bidder.criteo.com',
    // Outbrain
    'widgets.outbrain.com',
    'log.outbrain.com',
    'amplify.outbrain.com',
    // Taboola
    'cdn.taboola.com',
    'trc.taboola.com',
    'log.taboola.com',
    'nr-data.taboola.com',
    // Yandex Metrica
    'mc.yandex.ru',
    'mc.yandex.com',
    // Baidu Analytics
    'hm.baidu.com',
    // TikTok
    'analytics.tiktok.com',
    'ads-api.tiktok.com',
    'log.tiktokv.com',
    'ad.tiktok.com',
    // Snapchat
    'tr.snapchat.com',
    'sc-static.net',
    // Pinterest
    'log.pinterest.com',
    'ct.pinterest.com',
    'ads.pinterest.com',
    'trk.pinterest.com',
    // Reddit
    'alb.reddit.com',
    'pixel.reddit.com',
    'redd.it',
    // Nielsen
    'imrworldwide.com',
    'secure-dcr.imrworldwide.com',
    'cdn-gl.imrworldwide.com',
    // comScore
    'scorecardresearch.com',
    'sb.scorecardresearch.com',
    'pixel.scorecardresearch.com',
    'beacon.scorecardresearch.com',
    // Chartbeat
    'static.chartbeat.com',
    'ping.chartbeat.net',
    // Parse.ly
    'srv.pixel.parsely.com',
    'pixel.parsely.com',
    'api.parsely.com',
    // New Relic (browser agent)
    'bam.nr-data.net',
    'js-agent.newrelic.com',
    'nr-data.net',
    // AddThis
    's7.addthis.com',
    'm.addthis.com',
    'addthis.com',
    // ShareThis
    'w.sharethis.com',
    'platform-api.sharethis.com',
    // Disqus
    'a.disquscdn.com',
    'disqus.com',
    'disqusads.com',
    // DoubleVerify
    'cdn.doubleverify.com',
    'pub.doubleverify.com',
    'rtb.doubleverify.com',
    // Integral Ad Science
    'pixel.adsafeprotected.com',
    'fw.adsafeprotected.com',
    // Moat
    'tags.moatads.com',
    'z.moatads.com',
    // The Trade Desk
    'match.adsrvr.org',
    'insight.adsrvr.org',
    'adsrvr.org',
    // MediaMath
    'pixel.mathtag.com',
    'bh.contextweb.com',
    'mathtag.com',
    // Pubmatic
    'ads.pubmatic.com',
    'image.pubmatic.com',
    'simage2.pubmatic.com',
    // OpenX
    'us-u.openx.net',
    'openx.net',
    // Rubicon / Magnite
    'fastlane.rubiconproject.com',
    'beacon.rubiconproject.com',
    'rubiconproject.com',
    // Index Exchange
    'js-sec.indexww.com',
    'r.casalemedia.com',
    'casalemedia.com',
    // Sovrn
    'ap.lijit.com',
    'beacon.lijit.com',
    // Lucky Orange
    'd.luckyorange.net',
    'cs.luckyorange.net',
    // Mouseflow
    'cdn.mouseflow.com',
    'mouseflow.com',
    // LogRocket
    'cdn.lr-ingest.io',
    'r.lr-ingest.io',
    // Qualtrics
    'siteintercept.qualtrics.com',
    'qualtrics.com',
    // Optimizely
    'cdn.optimizely.com',
    'logx.optimizely.com',
    // VWO
    'dev.visualwebsiteoptimizer.com',
    'visualwebsiteoptimizer.com',
    // Crazy Egg
    'script.crazyegg.com',
    // LiveRamp
    'idsync.rlcdn.com',
    'rlcdn.com',
    // Oracle / BlueKai DMP
    'bluekai.com',
    'bkrtx.com',
    'nexac.com',
    // Krux / Salesforce DMP
    'krxd.net',
    // BidSwitch
    'bidswitch.net',
    // Smart AdServer
    'smartadserver.com',
    'sskzlv.com',
    // ShareThrough
    'sharethrough.com',
    // TripleLift
    'triplelift.com',
    '3lift.com',
    // Sonobi
    'sonobi.com',
    // District M
    'districtm.io',
    // EMX Digital
    'emxdgt.com',
    // 33Across
    '33across.com',
    'tynt.com',
    // Conversant / Epsilon
    'conversantmedia.com',
    'epsilon.com',
    // AdRoll
    'adroll.com',
    'd.adroll.com',
    // Yieldmo
    'yieldmo.com',
    // Kargo
    'kargo.com',
    // SpotX
    'spotx.tv',
    'spotxchange.com',
    // FreeWheel
    'freewheel.tv',
    'adtechfwd.com',
    // Teads
    'teads.tv',
    'teads.com',
    // Nativo
    'nativo.com',
    'postrelease.com',
    // Sizmek
    'serving-sys.com',
    'mediamind.com',
    // Exponential (Tribal Fusion)
    'exponential.com',
    'tribalfusion.com',
    // Conversant / ValueClick
    'valueclick.com',
    'fastclick.net',
    // Undertone
    'undertone.com',
    // GumGum
    'gumgum.com',
    // Lotame
    'crwdcntrl.net',
    'lotame.com',
    // LiveIntent
    'liadm.com',
    'liveintent.com',
    // SessionCam
    'sessioncam.com',
    // ClickTale
    'clicktale.net',
    'clicktale.com',
    // Pendo
    'pendo.io',
    'cdn.pendo.io',
    // Appcues
    'appcues.com',
    'fast.appcues.com',
    // WalkMe
    'walkme.com',
    'cdn.walkme.com',
    // Drift / Driftt
    'drift.com',
    'driftt.com',
    'js.driftt.com',
    // Klaviyo
    'klaviyo.com',
    'static.klaviyo.com',
    // Braze / Appboy
    'braze.com',
    'appboy.com',
    'iad.appboy.com',
    // OneSignal
    'onesignal.com',
    'cdn.onesignal.com',
    // Iterable
    'iterable.com',
    // Sailthru
    'sailthru.com',
    // Threat Metrix / LexisNexis
    'threatmetrix.com',
    'h.online-metrix.net',
    // Kount
    'kount.net',
    // Sift
    'sift.com',
    'siftscience.com',
    // Adform
    'adform.net',
    'track.adform.net',
    // MediaNet
    'media.net',
    // Yahoo / Verizon Media
    'yahoo.com',
    'yimg.com',
    'advertising.yahoo.com',
    // Zemanta
    'zemanta.com',
    // Bidtellect
    'bidtellect.com',
    // Amobee
    'amobee.com',
    'turn.com',
    'tribalfusion.com',
    // Pulsepoint
    'pulsepoint.com',
    'contextweb.com',
    // Xaxis
    'xaxis.com',
    // Dstillery
    'dstillery.com',
    'media6degrees.com',
    // Eyeota
    'eyeota.net',
    // Bombora
    'bombora.com',
    // Dataxu
    'dataxu.com',
]);
/**
 * Returns true if the given hostname (or any parent domain) is a known tracker.
 */
function isTrackerDomain(hostname) {
    if (TRACKER_DOMAINS.has(hostname))
        return true;
    // Walk up subdomains: e.g. "foo.bar.google-analytics.com" → check "bar.google-analytics.com", "google-analytics.com"
    const parts = hostname.split('.');
    for (let i = 1; i < parts.length - 1; i++) {
        if (TRACKER_DOMAINS.has(parts.slice(i).join('.')))
            return true;
    }
    return false;
}

;// ./src/background/index.ts
// MV3 Service Worker background.
// declarativeNetRequest handles tracker blocking (see rules.json).
// chrome.scripting dynamically registers canvas.js / webrtc.js into the MAIN
// world so they bypass page CSP and can be toggled independently per setting.


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
// ── Dynamic content script registration ───────────────────────────────────
// canvas.js and webrtc.js run in MAIN world, bypassing page CSP.
// We register/unregister them so settings take effect on the next page load.
const CANVAS_ID = 'eidolon-canvas';
const WEBRTC_ID = 'eidolon-webrtc';
async function syncContentScripts(enabled, settings) {
    const registered = await chrome.scripting.getRegisteredContentScripts();
    const ids = new Set(registered.map((s) => s.id));
    const wantCanvas = enabled && settings.spoofCanvas;
    const wantWebRTC = enabled && settings.blockWebRTC;
    if (wantCanvas && !ids.has(CANVAS_ID)) {
        await chrome.scripting.registerContentScripts([{
                id: CANVAS_ID, matches: ['<all_urls>'], js: ['canvas.js'],
                runAt: 'document_start', world: 'MAIN', allFrames: true,
            }]);
    }
    else if (!wantCanvas && ids.has(CANVAS_ID)) {
        await chrome.scripting.unregisterContentScripts({ ids: [CANVAS_ID] });
    }
    if (wantWebRTC && !ids.has(WEBRTC_ID)) {
        await chrome.scripting.registerContentScripts([{
                id: WEBRTC_ID, matches: ['<all_urls>'], js: ['webrtc.js'],
                runAt: 'document_start', world: 'MAIN', allFrames: true,
            }]);
    }
    else if (!wantWebRTC && ids.has(WEBRTC_ID)) {
        await chrome.scripting.unregisterContentScripts({ ids: [WEBRTC_ID] });
    }
}
async function syncRulesets(enabled, settings) {
    const shouldBlock = enabled && settings.blockTrackers;
    await chrome.declarativeNetRequest.updateEnabledRulesets(shouldBlock
        ? { enableRulesetIds: ['tracker-rules'], disableRulesetIds: [] }
        : { enableRulesetIds: [], disableRulesetIds: ['tracker-rules'] });
}
// Sync on install/update. Dynamic registrations persist across service-worker
// restarts so we don't need a startup IIFE — onInstalled covers both fresh
// install and dev-mode reload (which Chrome treats as an update).
chrome.runtime.onInstalled.addListener(async () => {
    const [state, settings] = await Promise.all([loadState(), loadSettings()]);
    await Promise.all([syncContentScripts(state.enabled, settings), syncRulesets(state.enabled, settings)]);
});
// ── webRequest observer ────────────────────────────────────────────────────
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
    if (!state.tabs[tabId]) {
        state.tabs[tabId] = {
            url: '', title: '', blocked: [],
            webrtcBlocked: false, canvasSpoofed: false, lastUpdated: Date.now(),
        };
    }
    const blocked = { url, type, reason: 'tracker', timestamp: Date.now(), domain };
    state.tabs[tabId].blocked.push(blocked);
    state.tabs[tabId].lastUpdated = Date.now();
    state.totalBlocked++;
    await saveState(state);
    chrome.runtime.sendMessage({ type: 'BLOCKED', tabId, blocked }).catch(() => { });
}
// ── Tab lifecycle ──────────────────────────────────────────────────────────
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    if (changeInfo.status === 'loading' && changeInfo.url) {
        const state = await loadState();
        state.tabs[tabId] = {
            url: changeInfo.url, title: '',
            blocked: [], webrtcBlocked: false, canvasSpoofed: false,
            lastUpdated: Date.now(),
        };
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
                if (!state.tabs[sender.tab.id]) {
                    state.tabs[sender.tab.id] = {
                        url: '', title: '', blocked: [],
                        webrtcBlocked: false, canvasSpoofed: false, lastUpdated: Date.now(),
                    };
                }
                state.tabs[sender.tab.id].canvasSpoofed = true;
                await saveState(state);
            }
            return null;
        case 'WEBRTC_BLOCKED':
            if (sender.tab?.id != null) {
                if (!state.tabs[sender.tab.id]) {
                    state.tabs[sender.tab.id] = {
                        url: '', title: '', blocked: [],
                        webrtcBlocked: false, canvasSpoofed: false, lastUpdated: Date.now(),
                    };
                }
                state.tabs[sender.tab.id].webrtcBlocked = true;
                await saveState(state);
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