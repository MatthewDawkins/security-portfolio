// Content script — isolated world, document_start.
// Forwards status notifications from MAIN-world scripts to the background:
//   - canvas.js / webrtc.js call chrome.runtime.sendMessage directly (N/A from MAIN world)
//     so we use this script to send them after reading storage.
//   - audio.js / webgl.js / fonts.js / hardware.js fire CustomEvents on window
//     which this script listens for and forwards as FINGERPRINT_PROBE messages.

import { DEFAULT_SETTINGS, FingerprintProbe, Settings } from '../shared/types'

chrome.storage.local.get(['enabled', 'settings'], (result) => {
  const enabled = result.enabled !== false
  if (!enabled) return

  const settings: Settings = { ...DEFAULT_SETTINGS, ...(result.settings ?? {}) }

  // Notify background that defenses are active on this tab
  if (settings.spoofCanvas)  chrome.runtime.sendMessage({ type: 'CANVAS_SPOOFED' }).catch(() => {})
  if (settings.blockWebRTC)  chrome.runtime.sendMessage({ type: 'WEBRTC_BLOCKED' }).catch(() => {})
})

// Forward fingerprint probe detections from MAIN-world detector scripts.
// The CustomEvent 'eidolon-probe' is dispatched by audio.js, webgl.js, fonts.js, hardware.js.
window.addEventListener('eidolon-probe', (e: Event) => {
  const { detail } = e as CustomEvent<{ type: string; detail: string }>
  if (!detail?.type) return

  const probe: FingerprintProbe = {
    type: detail.type as FingerprintProbe['type'],
    detail: detail.detail,
    timestamp: Date.now(),
  }

  chrome.runtime.sendMessage({ type: 'FINGERPRINT_PROBE', probe }).catch(() => {})
})
