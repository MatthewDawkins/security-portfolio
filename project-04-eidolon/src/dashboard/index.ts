import { BlockedRequest, ExtensionState, TabData } from '../shared/types'

function sendMessage<T>(message: object): Promise<T> {
  return new Promise((resolve) => chrome.runtime.sendMessage(message, resolve))
}

function timeAgo(ts: number): string {
  const s = Math.floor((Date.now() - ts) / 1000)
  if (s < 60)  return `${s}s ago`
  if (s < 3600) return `${Math.floor(s / 60)}m ago`
  return `${Math.floor(s / 3600)}h ago`
}

function domainOf(url: string): string {
  try { return new URL(url).hostname.replace(/^www\./, '') }
  catch { return url }
}

function buildTabCard(tabId: string, data: TabData): HTMLElement {
  const card = document.createElement('div')
  card.className = 'tab-card'

  const pageTitle  = data.title || domainOf(data.url) || `Tab ${tabId}`
  const pageUrl    = data.url
  const blockCount = data.blocked.length

  card.innerHTML = `
    <div class="tab-header">
      <span class="chevron">&#9658;</span>
      <span class="tab-url">
        <strong>${pageTitle}</strong>
        &nbsp;
        ${pageUrl}
      </span>
      ${data.canvasSpoofed ? '<span class="badge green">canvas ✓</span>' : ''}
      ${data.webrtcBlocked ? '<span class="badge green">webrtc ✓</span>' : ''}
      <span class="badge ${blockCount > 0 ? '' : 'zero'}">
        ${blockCount > 0 ? `&#128683; ${blockCount} blocked` : '0 blocked'}
      </span>
    </div>
    <div class="request-table">
      ${blockCount > 0 ? `
        <div class="request-row header">
          <span>Domain</span>
          <span>Request type</span>
          <span>Reason</span>
          <span style="text-align:right">Time</span>
        </div>
        ${[...data.blocked].reverse().map((r: BlockedRequest) => `
          <div class="request-row">
            <span class="domain" title="${r.url}">${r.domain}</span>
            <span class="type">${r.type}</span>
            <span class="reason">${r.reason}</span>
            <span class="time">${timeAgo(r.timestamp)}</span>
          </div>
        `).join('')}
      ` : `
        <div style="padding: 14px 16px; color: #4a5568; font-size: 11px;">
          No requests blocked on this page.
        </div>
      `}
    </div>
  `

  // Toggle card open/closed
  card.querySelector('.tab-header')!.addEventListener('click', () => {
    card.classList.toggle('open')
  })

  return card
}

async function render() {
  const response = await sendMessage<{ data: ExtensionState }>({ type: 'GET_STATE' })
  const state = response?.data
  if (!state) return

  document.getElementById('total-blocked')!.textContent = String(state.totalBlocked)

  const entries = Object.entries(state.tabs)
  document.getElementById('tabs-active')!.textContent = String(entries.length)

  const container = document.getElementById('tabs-container')!
  container.innerHTML = ''

  if (entries.length === 0) {
    container.innerHTML = `
      <div class="empty-tabs">
        <p>No tab data yet.</p>
        <small>Browse a few pages and come back.</small>
      </div>
    `
    return
  }

  // Sort: most blocked first
  entries.sort(([, a], [, b]) => b.blocked.length - a.blocked.length)

  for (const [tabId, data] of entries) {
    container.appendChild(buildTabCard(tabId, data))
  }
}

document.getElementById('refresh-btn')!.addEventListener('click', render)

// Auto-refresh every 3s
render()
setInterval(render, 3000)
