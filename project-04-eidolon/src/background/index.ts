// MV3 Service Worker background.
// declarativeNetRequest handles tracker blocking (see rules.json).
// chrome.scripting dynamically registers canvas.js / webrtc.js into the MAIN
// world so they bypass page CSP and can be toggled independently per setting.

import { BlockedRequest, ExtensionState, TabData, Settings, DEFAULT_SETTINGS } from '../shared/types'
import { isTrackerDomain } from '../shared/tracker-domains'

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

// ── Dynamic content script registration ───────────────────────────────────
// canvas.js and webrtc.js run in MAIN world, bypassing page CSP.
// We register/unregister them so settings take effect on the next page load.

const CANVAS_ID = 'eidolon-canvas'
const WEBRTC_ID = 'eidolon-webrtc'

async function syncContentScripts(enabled: boolean, settings: Settings): Promise<void> {
  const registered = await chrome.scripting.getRegisteredContentScripts()
  const ids = new Set(registered.map((s) => s.id))

  const wantCanvas = enabled && settings.spoofCanvas
  const wantWebRTC = enabled && settings.blockWebRTC

  if (wantCanvas && !ids.has(CANVAS_ID)) {
    await chrome.scripting.registerContentScripts([{
      id: CANVAS_ID, matches: ['<all_urls>'], js: ['canvas.js'],
      runAt: 'document_start', world: 'MAIN', allFrames: true,
    }])
  } else if (!wantCanvas && ids.has(CANVAS_ID)) {
    await chrome.scripting.unregisterContentScripts({ ids: [CANVAS_ID] })
  }

  if (wantWebRTC && !ids.has(WEBRTC_ID)) {
    await chrome.scripting.registerContentScripts([{
      id: WEBRTC_ID, matches: ['<all_urls>'], js: ['webrtc.js'],
      runAt: 'document_start', world: 'MAIN', allFrames: true,
    }])
  } else if (!wantWebRTC && ids.has(WEBRTC_ID)) {
    await chrome.scripting.unregisterContentScripts({ ids: [WEBRTC_ID] })
  }
}

async function syncRulesets(enabled: boolean, settings: Settings): Promise<void> {
  const shouldBlock = enabled && settings.blockTrackers
  await chrome.declarativeNetRequest.updateEnabledRulesets(
    shouldBlock
      ? { enableRulesetIds: ['tracker-rules'], disableRulesetIds: [] }
      : { enableRulesetIds: [], disableRulesetIds: ['tracker-rules'] }
  )
}

// Sync on install/update. Dynamic registrations persist across service-worker
// restarts so we don't need a startup IIFE — onInstalled covers both fresh
// install and dev-mode reload (which Chrome treats as an update).
chrome.runtime.onInstalled.addListener(async () => {
  const [state, settings] = await Promise.all([loadState(), loadSettings()])
  await Promise.all([syncContentScripts(state.enabled, settings), syncRulesets(state.enabled, settings)])
})

// ── webRequest observer ────────────────────────────────────────────────────

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

  if (!state.tabs[tabId]) {
    state.tabs[tabId] = {
      url: '', title: '', blocked: [],
      webrtcBlocked: false, canvasSpoofed: false, lastUpdated: Date.now(),
    }
  }

  const blocked: BlockedRequest = { url, type, reason: 'tracker', timestamp: Date.now(), domain }
  state.tabs[tabId].blocked.push(blocked)
  state.tabs[tabId].lastUpdated = Date.now()
  state.totalBlocked++

  await saveState(state)
  chrome.runtime.sendMessage({ type: 'BLOCKED', tabId, blocked }).catch(() => {})
}

// ── Tab lifecycle ──────────────────────────────────────────────────────────

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status === 'loading' && changeInfo.url) {
    const state = await loadState()
    state.tabs[tabId] = {
      url: changeInfo.url, title: '',
      blocked: [], webrtcBlocked: false, canvasSpoofed: false,
      lastUpdated: Date.now(),
    }
    await saveState(state)
    return
  }

  if (changeInfo.url || changeInfo.title) {
    const state = await loadState()
    if (state.tabs[tabId]) {
      if (changeInfo.url) state.tabs[tabId].url   = changeInfo.url
      if (tab.title)      state.tabs[tabId].title = tab.title
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
  message: { type: string; tabId?: number; settings?: Settings },
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
        if (!state.tabs[sender.tab.id]) {
          state.tabs[sender.tab.id] = {
            url: '', title: '', blocked: [],
            webrtcBlocked: false, canvasSpoofed: false, lastUpdated: Date.now(),
          }
        }
        state.tabs[sender.tab.id].canvasSpoofed = true
        await saveState(state)
      }
      return null

    case 'WEBRTC_BLOCKED':
      if (sender.tab?.id != null) {
        if (!state.tabs[sender.tab.id]) {
          state.tabs[sender.tab.id] = {
            url: '', title: '', blocked: [],
            webrtcBlocked: false, canvasSpoofed: false, lastUpdated: Date.now(),
          }
        }
        state.tabs[sender.tab.id].webrtcBlocked = true
        await saveState(state)
      }
      return null

    case 'OPEN_DASHBOARD':
      chrome.tabs.create({ url: chrome.runtime.getURL('dashboard.html') })
      return null

    default:
      return null
  }
}
