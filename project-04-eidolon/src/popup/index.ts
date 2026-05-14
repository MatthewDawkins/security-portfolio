import { ExtensionState, TabData, ThreatCategory, CATEGORY_META, FingerprintProbeType } from '../shared/types'
import { computePrivacyScore } from '../shared/privacy-score'

function sendMessage<T>(message: object): Promise<T> {
  return new Promise((resolve) => chrome.runtime.sendMessage(message, resolve))
}

function getCurrentTabId(): Promise<number | undefined> {
  return new Promise((resolve) => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => resolve(tabs[0]?.id))
  })
}

// ── Score ring ──────────────────────────────────────────────────────────────
// Circumference of the SVG circle (r=27): 2πr ≈ 169.6
const CIRCUMFERENCE = 2 * Math.PI * 27

function updateScoreRing(score: number, color: string, label: string) {
  const arc = document.getElementById('score-arc') as unknown as SVGCircleElement
  const num = document.getElementById('score-number')!
  const lbl = document.getElementById('score-label')!

  const offset = CIRCUMFERENCE * (1 - score / 100)
  arc.style.strokeDashoffset = String(offset)
  arc.style.stroke = color
  num.textContent = String(score)
  num.style.color = color
  lbl.textContent = label
  lbl.style.color = color
}

// ── Category list ───────────────────────────────────────────────────────────

// Category display order — highest severity first
const CATEGORY_ORDER: ThreatCategory[] = [
  'fraud-detection',
  'data-broker',
  'session-replay',
  'social-tracking',
  'behavioral-analytics',
  'marketing-automation',
  'ad-network',
  'ab-testing',
  'telemetry',
]

function renderCategoryList(categoryBreakdown: Partial<Record<ThreatCategory, number>>) {
  const list = document.getElementById('category-list')!
  const clean = document.getElementById('clean-state')!

  const categories = CATEGORY_ORDER.filter((c) => (categoryBreakdown[c] ?? 0) > 0)

  // Remove previous rows
  list.querySelectorAll('.category-row').forEach((el) => el.remove())

  if (categories.length === 0) {
    clean.style.display = 'flex'
    return
  }

  clean.style.display = 'none'

  for (const cat of categories) {
    const meta = CATEGORY_META[cat]
    const count = categoryBreakdown[cat]!
    const row = document.createElement('div')
    row.className = 'category-row'
    row.innerHTML = `
      <div class="cat-dot" style="background:${meta.color}"></div>
      <span class="cat-name">${meta.label}</span>
      <span class="cat-count"><strong>${count}</strong> domain${count !== 1 ? 's' : ''}</span>
    `
    list.appendChild(row)
  }
}

// ── Fingerprint defense grid ────────────────────────────────────────────────

function renderDefenseGrid(
  canvasSpoofed: boolean,
  webrtcBlocked: boolean,
  enabled: boolean,
  probesDetected: FingerprintProbeType[]
) {
  const probeSet = new Set(probesDetected)

  function setDefense(id: string, state: 'active' | 'detected' | 'inactive', symbol: string) {
    const el = document.getElementById(id)!
    el.textContent = symbol
    el.className = `defense-icon ${state}`
  }

  setDefense('def-canvas',   enabled && canvasSpoofed ? 'active'   : 'inactive', enabled && canvasSpoofed ? '✓' : '○')
  setDefense('def-webrtc',   enabled && webrtcBlocked  ? 'active'   : 'inactive', enabled && webrtcBlocked  ? '✓' : '○')
  setDefense('def-audio',    probeSet.has('audio')    ? 'detected' : 'active',   probeSet.has('audio')    ? '⚠' : '✓')
  setDefense('def-webgl',    probeSet.has('webgl')    ? 'detected' : 'active',   probeSet.has('webgl')    ? '⚠' : '✓')
  setDefense('def-font',     probeSet.has('font')     ? 'detected' : 'active',   probeSet.has('font')     ? '⚠' : '✓')
  setDefense('def-hardware', probeSet.has('hardware') ? 'detected' : 'active',   probeSet.has('hardware') ? '⚠' : '✓')
}

// ── Main render ─────────────────────────────────────────────────────────────

async function render() {
  const tabId = await getCurrentTabId()
  const response = await sendMessage<{ data: ExtensionState }>({ type: 'GET_STATE' })
  const state = response?.data
  if (!state) return

  const enabled: boolean = state.enabled
  const tabData: TabData | null = tabId != null
    ? (await sendMessage<{ data: TabData | null }>({ type: 'GET_TAB_DATA', tabId }))?.data ?? null
    : null

  // Toggle button
  const toggle = document.getElementById('toggle') as HTMLButtonElement
  toggle.textContent = enabled ? 'ON' : 'OFF'
  toggle.className = `toggle${enabled ? '' : ' off'}`

  // Status
  document.getElementById('dot')!.className = `dot${enabled ? '' : ' off'}`
  document.getElementById('status-text')!.textContent = enabled
    ? 'Privacy Intelligence Active'
    : 'Protection Disabled'

  // Score
  const emptyTab: TabData = {
    url: '', title: '', blocked: [], fingerprintProbes: [],
    webrtcBlocked: false, canvasSpoofed: false, lastUpdated: 0,
  }
  const tab = enabled ? (tabData ?? emptyTab) : emptyTab
  const ps = computePrivacyScore(tab)

  if (enabled) {
    updateScoreRing(ps.score, ps.color, ps.label)
  } else {
    updateScoreRing(0, '#4a5568', 'Disabled')
  }

  document.getElementById('blocked-count')!.textContent = String(tab.blocked.length)

  // Threat categories
  renderCategoryList(enabled ? ps.categoryBreakdown : {})

  // Fingerprint defense
  renderDefenseGrid(tab.canvasSpoofed, tab.webrtcBlocked, enabled, enabled ? ps.probesDetected : [])
}

// ── Event listeners ─────────────────────────────────────────────────────────

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

// Live updates while popup is open
chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === 'BLOCKED' || msg.type === 'PROBE_DETECTED') render()
})

render()
setInterval(render, 2000)
