import { BlockedRequest, ExtensionState, TabData } from '../shared/types'

function sendMessage<T>(message: object): Promise<T> {
  return new Promise((resolve) => chrome.runtime.sendMessage(message, resolve))
}

function getCurrentTabId(): Promise<number | undefined> {
  return new Promise((resolve) => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      resolve(tabs[0]?.id)
    })
  })
}

function formatDomain(url: string): string {
  try {
    return new URL(url).hostname.replace(/^www\./, '')
  } catch {
    return url
  }
}

function renderBlockedList(blocked: BlockedRequest[]) {
  const list = document.getElementById('blocked-list')!
  const empty = document.getElementById('empty-state')!

  // Remove old items (keep empty-state node)
  const items = list.querySelectorAll('.blocked-item')
  items.forEach((el) => el.remove())

  if (blocked.length === 0) {
    empty.style.display = 'block'
    return
  }

  empty.style.display = 'none'

  // Show up to 8 most recent, newest first
  const recent = [...blocked].reverse().slice(0, 8)
  for (const req of recent) {
    const item = document.createElement('div')
    item.className = 'blocked-item'
    item.innerHTML = `
      <div class="blocked-dot"></div>
      <span class="blocked-domain" title="${req.domain}">${req.domain}</span>
      <span class="blocked-type">${req.type}</span>
    `
    list.appendChild(item)
  }
}

async function render() {
  const tabId = await getCurrentTabId()
  const response = await sendMessage<{ data: ExtensionState }>({ type: 'GET_STATE' })
  const state = response?.data
  if (!state) return

  const enabled: boolean = state.enabled
  const tabData: TabData | undefined = tabId != null ? state.tabs[tabId] : undefined

  // Toggle button
  const toggle = document.getElementById('toggle') as HTMLButtonElement
  toggle.textContent = enabled ? 'ON' : 'OFF'
  toggle.className   = `toggle ${enabled ? '' : 'off'}`

  // Status bar
  document.getElementById('dot')!.className         = `dot ${enabled ? '' : 'off'}`
  document.getElementById('status-text')!.textContent = enabled ? 'Protected' : 'Disabled'

  // Stats
  const count = tabData?.blocked.length ?? 0
  document.getElementById('blocked-count')!.textContent = String(count)

  const canvasEl = document.getElementById('canvas-val')!
  canvasEl.textContent = !enabled ? '✗' : tabData?.canvasSpoofed ? '✓' : '…'
  canvasEl.className   = `stat-value ${!enabled ? 'inactive' : ''}`

  const webrtcEl = document.getElementById('webrtc-val')!
  webrtcEl.textContent = !enabled ? '✗' : tabData?.webrtcBlocked ? '✓' : '…'
  webrtcEl.className   = `stat-value ${!enabled ? 'inactive' : ''}`

  // Blocked request list
  renderBlockedList(tabData?.blocked ?? [])
}

// ── Event listeners ────────────────────────────────────────────────────────

document.getElementById('toggle')!.addEventListener('click', async () => {
  await sendMessage({ type: 'TOGGLE_ENABLED' })
  render()
})

document.getElementById('dashboard-btn')!.addEventListener('click', () => {
  chrome.tabs.create({ url: chrome.runtime.getURL('dashboard.html') })
  window.close()
})

document.getElementById('settings-btn')!.addEventListener('click', () => {
  chrome.tabs.create({ url: chrome.runtime.getURL('settings.html') })
  window.close()
})

// Listen for live block events from background while popup is open
chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === 'BLOCKED') render()
})

// Initial render + light polling fallback
render()
setInterval(render, 1500)
