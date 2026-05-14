import { BlockedRequest, CATEGORY_META, ExtensionState, FingerprintProbe, TabData, ThreatCategory } from '../shared/types'
import { computePrivacyScore } from '../shared/privacy-score'

function sendMessage<T>(message: object): Promise<T> {
  return new Promise((resolve) => chrome.runtime.sendMessage(message, resolve))
}

function timeAgo(ts: number): string {
  const s = Math.floor((Date.now() - ts) / 1000)
  if (s < 60)   return `${s}s ago`
  if (s < 3600) return `${Math.floor(s / 60)}m ago`
  return `${Math.floor(s / 3600)}h ago`
}

function domainOf(url: string): string {
  try { return new URL(url).hostname.replace(/^www\./, '') }
  catch { return url }
}

// ── Category chips ──────────────────────────────────────────────────────────

function buildCategoryChips(breakdown: Partial<Record<ThreatCategory, number>>): string {
  return Object.entries(breakdown)
    .map(([cat, count]) => {
      const meta = CATEGORY_META[cat as ThreatCategory]
      return `<div class="cat-chip">
        <div class="cat-chip-dot" style="background:${meta.color}"></div>
        ${meta.label} <strong style="color:#e2e8f0;margin-left:2px">${count}</strong>
      </div>`
    })
    .join('')
}

// ── Probe chips ─────────────────────────────────────────────────────────────

const PROBE_LABELS: Record<string, string> = {
  audio:    'Audio FP',
  webgl:    'WebGL FP',
  font:     'Font Enum',
  hardware: 'Hardware Profile',
}

function buildProbeChips(probes: FingerprintProbe[]): string {
  if (probes.length === 0) return ''
  const types = [...new Set(probes.map((p) => p.type))]
  return types.map((t) => `<div class="probe-chip">⚠ ${PROBE_LABELS[t] ?? t}</div>`).join('')
}

function buildProbeDetails(probes: FingerprintProbe[]): string {
  if (probes.length === 0) return ''
  return probes.map((p) => `<div class="probe-detail-row">${p.detail}</div>`).join('')
}

// ── Request table ───────────────────────────────────────────────────────────

function buildRequestTable(blocked: BlockedRequest[]): string {
  if (blocked.length === 0) {
    return '<div style="padding:10px 14px;color:#4a5568;font-size:10px">No requests blocked on this page.</div>'
  }

  const rows = [...blocked]
    .reverse()
    .map((r) => {
      const meta = CATEGORY_META[r.category]
      return `<div class="request-row">
        <span class="req-domain" title="${r.url}">${r.domain}</span>
        <span class="req-type">${r.type}</span>
        <span class="req-cat" style="color:${meta.color}">${meta.label}</span>
        <span class="req-time">${timeAgo(r.timestamp)}</span>
      </div>`
    })
    .join('')

  return `
    <div class="request-row hdr">
      <span>Domain</span>
      <span>Type</span>
      <span>Category</span>
      <span style="text-align:right">Time</span>
    </div>
    ${rows}
  `
}

// ── Tab card ────────────────────────────────────────────────────────────────

function buildTabCard(tabId: string, data: TabData): HTMLElement {
  const ps = computePrivacyScore(data)
  const title = data.title || domainOf(data.url) || `Tab ${tabId}`
  const blockCount = data.blocked.length
  const probeCount = data.fingerprintProbes.length
  const hasCats = Object.keys(ps.categoryBreakdown).length > 0

  const card = document.createElement('div')
  card.className = 'tab-card'

  const probeWarning = probeCount > 0
    ? `<div class="badge warn">⚠ ${probeCount} FP probe${probeCount !== 1 ? 's' : ''}</div>`
    : ''

  const blockBadge = blockCount > 0
    ? `<div class="badge">${blockCount} blocked</div>`
    : `<div class="badge zero">0 blocked</div>`

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
        ${data.webrtcBlocked  ? '<div class="badge green">webrtc ✓</div>' : ''}
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
  `

  card.querySelector('.tab-header')!.addEventListener('click', () => card.classList.toggle('open'))
  return card
}

// ── Main render ─────────────────────────────────────────────────────────────

async function render() {
  const response = await sendMessage<{ data: ExtensionState }>({ type: 'GET_STATE' })
  const state = response?.data
  if (!state) return

  const entries = Object.entries(state.tabs)

  // Summary tiles
  document.getElementById('total-blocked')!.textContent = String(state.totalBlocked)
  document.getElementById('tabs-active')!.textContent  = String(entries.length)

  const totalProbes = entries.reduce(
    (sum, [, tab]) => sum + tab.fingerprintProbes.length, 0
  )
  document.getElementById('total-probes')!.textContent = String(totalProbes)

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

  // Sort: highest threat first (lowest score first), then most blocked
  entries.sort(([, a], [, b]) => {
    const sa = computePrivacyScore(a).score
    const sb = computePrivacyScore(b).score
    if (sa !== sb) return sa - sb
    return b.blocked.length - a.blocked.length
  })

  for (const [tabId, data] of entries) {
    container.appendChild(buildTabCard(tabId, data))
  }
}

document.getElementById('refresh-btn')!.addEventListener('click', render)

render()
setInterval(render, 3000)
