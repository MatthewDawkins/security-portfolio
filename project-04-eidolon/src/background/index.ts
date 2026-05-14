// MV3 Service Worker background.
// declarativeNetRequest handles tracker blocking (rules.json).
// chrome.scripting dynamically registers MAIN-world scripts — both defenses
// (canvas spoofing, WebRTC relay-only) and detectors (audio, webgl, fonts, hardware).

import {
  BlockedRequest,
  ExtensionState,
  FingerprintProbe,
  Settings,
  DEFAULT_SETTINGS,
  TabData,
} from '../shared/types'
import { getTrackerCategory, isTrackerDomain } from '../shared/tracker-domains'

// ── Storage helpers ────────────────────────────────────────────────────────

async function loadState(): Promise<ExtensionState> {
  return new Promise((resolve) => {
    chrome.storage.local.get(['enabled', 'totalBlocked', 'tabs'], (result) => {
      resolve({
        enabled: result.enabled !== false,
        totalBlocked: (result.totalBlocked as number) || 0,
        tabs: (result.tabs as Record<number, TabData>) || {},
      })
    })
  })
}

async function saveState(state: ExtensionState): Promise<void> {
  return new Promise((resolve) => {
    chrome.storage.local.set(
      { enabled: state.enabled, totalBlocked: state.totalBlocked, tabs: state.tabs },
      resolve
    )
  })
}

async function loadSettings(): Promise<Settings> {
  return new Promise((resolve) => {
    chrome.storage.local.get(['settings'], (result) => {
      resolve({ ...DEFAULT_SETTINGS, ...(result.settings as Partial<Settings> ?? {}) })
    })
  })
}

async function saveSettings(settings: Settings): Promise<void> {
  return new Promise((resolve) => {
    chrome.storage.local.set({ settings }, resolve)
  })
}

// ── Content script IDs ────────────────────────────────────────────────────
// Defenses run in MAIN world to bypass CSP and intercept APIs before page scripts.
// Detectors also run in MAIN world to intercept API calls and fire CustomEvents
// that content.js (isolated world) listens for and forwards to background.

const SCRIPT_IDS = {
  canvas:   'eidolon-canvas',
  webrtc:   'eidolon-webrtc',
  audio:    'eidolon-audio',
  webgl:    'eidolon-webgl',
  fonts:    'eidolon-fonts',
  hardware: 'eidolon-hardware',
} as const

type ScriptKey = keyof typeof SCRIPT_IDS

async function syncContentScripts(enabled: boolean, settings: Settings): Promise<void> {
  const registered = await chrome.scripting.getRegisteredContentScripts()
  const activeIds = new Set(registered.map((s) => s.id))

  const desired: Record<ScriptKey, boolean> = {
    canvas:   enabled && settings.spoofCanvas,
    webrtc:   enabled && settings.blockWebRTC,
    audio:    enabled && settings.detectAudioFingerprint,
    webgl:    enabled && settings.detectWebGLFingerprint,
    fonts:    enabled && settings.detectFontEnumeration,
    hardware: enabled && settings.detectHardwareProbe,
  }

  const toRegister: chrome.scripting.RegisteredContentScript[] = []
  const toUnregister: string[] = []

  for (const [key, want] of Object.entries(desired) as [ScriptKey, boolean][]) {
    const id = SCRIPT_IDS[key]
    if (want && !activeIds.has(id)) {
      toRegister.push({
        id,
        matches: ['<all_urls>'],
        js: [`${key}.js`],
        runAt: 'document_start',
        world: 'MAIN',
        allFrames: true,
      })
    } else if (!want && activeIds.has(id)) {
      toUnregister.push(id)
    }
  }

  if (toRegister.length) await chrome.scripting.registerContentScripts(toRegister)
  if (toUnregister.length) await chrome.scripting.unregisterContentScripts({ ids: toUnregister })
}

async function syncRulesets(enabled: boolean, settings: Settings): Promise<void> {
  const shouldBlock = enabled && settings.blockTrackers
  await chrome.declarativeNetRequest.updateEnabledRulesets(
    shouldBlock
      ? { enableRulesetIds: ['tracker-rules'], disableRulesetIds: [] }
      : { enableRulesetIds: [], disableRulesetIds: ['tracker-rules'] }
  )
}

// ── Initialisation ────────────────────────────────────────────────────────

chrome.runtime.onInstalled.addListener(async () => {
  const [state, settings] = await Promise.all([loadState(), loadSettings()])
  await Promise.all([syncContentScripts(state.enabled, settings), syncRulesets(state.enabled, settings)])
})

// ── webRequest observer ────────────────────────────────────────────────────
// Observes requests to classify and record blocked trackers per tab.
// The actual network block is handled by declarativeNetRequest (rules.json).

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (details.tabId < 0) return
    let hostname: string
    try {
      hostname = new URL(details.url).hostname.replace(/^www\./, '')
    } catch {
      return
    }
    if (!isTrackerDomain(hostname)) return
    recordBlock(details.tabId, details.url, details.type, hostname)
  },
  { urls: ['<all_urls>'] }
)

async function recordBlock(tabId: number, url: string, type: string, domain: string) {
  const state = await loadState()
  if (!state.enabled) return

  const category = getTrackerCategory(domain) ?? 'ad-network'

  if (!state.tabs[tabId]) {
    state.tabs[tabId] = emptyTabData()
  }

  const blocked: BlockedRequest = { url, type, reason: 'tracker', timestamp: Date.now(), domain, category }
  state.tabs[tabId].blocked.push(blocked)
  state.tabs[tabId].lastUpdated = Date.now()
  state.totalBlocked++

  await saveState(state)
  chrome.runtime.sendMessage({ type: 'BLOCKED', tabId, blocked }).catch(() => {})
}

// ── Fingerprint probe recording ───────────────────────────────────────────

async function recordProbe(tabId: number, probe: FingerprintProbe) {
  const state = await loadState()
  if (!state.enabled) return

  if (!state.tabs[tabId]) {
    state.tabs[tabId] = emptyTabData()
  }

  // Deduplicate: only store the first occurrence of each probe type per tab
  const existing = state.tabs[tabId].fingerprintProbes
  if (!existing.some((p) => p.type === probe.type)) {
    existing.push(probe)
    state.tabs[tabId].lastUpdated = Date.now()
    await saveState(state)
    chrome.runtime.sendMessage({ type: 'PROBE_DETECTED', tabId, probe }).catch(() => {})
  }
}

// ── Tab lifecycle ──────────────────────────────────────────────────────────

function emptyTabData(): TabData {
  return {
    url: '', title: '', blocked: [], fingerprintProbes: [],
    webrtcBlocked: false, canvasSpoofed: false, lastUpdated: Date.now(),
  }
}

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status === 'loading' && changeInfo.url) {
    const state = await loadState()
    state.tabs[tabId] = { ...emptyTabData(), url: changeInfo.url }
    await saveState(state)
    return
  }

  if (changeInfo.url || changeInfo.title) {
    const state = await loadState()
    if (state.tabs[tabId]) {
      if (changeInfo.url)  state.tabs[tabId].url   = changeInfo.url
      if (tab.title)       state.tabs[tabId].title = tab.title
      await saveState(state)
    }
  }
})

chrome.tabs.onRemoved.addListener(async (tabId) => {
  const state = await loadState()
  delete state.tabs[tabId]
  await saveState(state)
})

// ── Message handling ───────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  handleMessage(message, sender).then(sendResponse).catch(() => sendResponse(null))
  return true
})

async function handleMessage(
  message: { type: string; tabId?: number; settings?: Settings; probe?: FingerprintProbe },
  sender: chrome.runtime.MessageSender
): Promise<unknown> {
  const state = await loadState()

  switch (message.type) {
    case 'GET_STATE':
      return { data: state }

    case 'GET_TAB_DATA':
      return { data: state.tabs[message.tabId!] ?? null }

    case 'TOGGLE_ENABLED': {
      state.enabled = !state.enabled
      await saveState(state)
      const settings = await loadSettings()
      await Promise.all([syncContentScripts(state.enabled, settings), syncRulesets(state.enabled, settings)])
      return { enabled: state.enabled }
    }

    case 'GET_SETTINGS':
      return { data: await loadSettings() }

    case 'SAVE_SETTINGS': {
      const newSettings = message.settings!
      await saveSettings(newSettings)
      await Promise.all([syncContentScripts(state.enabled, newSettings), syncRulesets(state.enabled, newSettings)])
      return { ok: true }
    }

    case 'CANVAS_SPOOFED':
      if (sender.tab?.id != null) {
        if (!state.tabs[sender.tab.id]) state.tabs[sender.tab.id] = emptyTabData()
        state.tabs[sender.tab.id].canvasSpoofed = true
        await saveState(state)
      }
      return null

    case 'WEBRTC_BLOCKED':
      if (sender.tab?.id != null) {
        if (!state.tabs[sender.tab.id]) state.tabs[sender.tab.id] = emptyTabData()
        state.tabs[sender.tab.id].webrtcBlocked = true
        await saveState(state)
      }
      return null

    case 'FINGERPRINT_PROBE':
      if (sender.tab?.id != null && message.probe) {
        await recordProbe(sender.tab.id, message.probe)
      }
      return null

    case 'OPEN_DASHBOARD':
      chrome.tabs.create({ url: chrome.runtime.getURL('dashboard.html') })
      return null

    default:
      return null
  }
}
