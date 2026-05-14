// Hardware profile detector — injected into MAIN world.
// No chrome.* APIs available here. Communicates detections via CustomEvent
// which content.js (isolated world) listens for and forwards to background.
//
// Detection: fingerprinters read multiple hardware attributes in quick succession
// to build a hardware profile: CPU count, RAM, touch support, platform string,
// screen color depth. If 4+ distinct attributes are read within 3 seconds, flag it.

const HARDWARE_PROPS: Array<{ obj: object; prop: string; label: string }> = [
  { obj: Navigator.prototype, prop: 'hardwareConcurrency', label: 'navigator.hardwareConcurrency' },
  { obj: Navigator.prototype, prop: 'deviceMemory',        label: 'navigator.deviceMemory' },
  { obj: Navigator.prototype, prop: 'maxTouchPoints',      label: 'navigator.maxTouchPoints' },
  { obj: Navigator.prototype, prop: 'platform',            label: 'navigator.platform' },
  { obj: Screen.prototype,    prop: 'colorDepth',          label: 'screen.colorDepth' },
  { obj: Screen.prototype,    prop: 'pixelDepth',          label: 'screen.pixelDepth' },
]

let probeCount = 0
let windowStart = Date.now()
let reported = false
const probed = new Set<string>()

function onHardwareAccess(label: string) {
  if (reported) return

  const now = Date.now()
  if (now - windowStart > 3000) {
    probeCount = 0
    probed.clear()
    windowStart = now
  }

  probed.add(label)
  probeCount = probed.size

  if (probeCount >= 4) {
    reported = true
    window.dispatchEvent(
      new CustomEvent('eidolon-probe', {
        detail: {
          type: 'hardware',
          detail:
            `Hardware profiling probe detected — ${probeCount} hardware attributes read within 3 seconds ` +
            `(${[...probed].join(', ')}). ` +
            'Scripts correlate CPU count, RAM, touch support, and screen geometry to build a device fingerprint.',
        },
      })
    )
  }
}

for (const { obj, prop, label } of HARDWARE_PROPS) {
  const desc = Object.getOwnPropertyDescriptor(obj, prop)
  if (!desc?.get) continue

  const origGet = desc.get
  Object.defineProperty(obj, prop, {
    get() {
      onHardwareAccess(label)
      return origGet.call(this)
    },
    configurable: true,
    enumerable: desc.enumerable,
  })
}
