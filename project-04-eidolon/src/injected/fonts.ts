// Font enumeration detector — injected into MAIN world.
// No chrome.* APIs available here. Communicates detections via CustomEvent
// which content.js (isolated world) listens for and forwards to background.
//
// Detection: font fingerprinting sets ctx.font to many different font families
// and calls measureText() to detect installed fonts by width differences.
// We track unique font-family names set on canvas contexts — if more than 15
// unique families are probed within a 5-second window, flag it.

const fontDesc = Object.getOwnPropertyDescriptor(CanvasRenderingContext2D.prototype, 'font')

if (fontDesc?.set) {
  const origSet = fontDesc.set

  let fontsSeen = new Set<string>()
  let windowStart = Date.now()
  let reported = false

  // Minimal font-family extractor — handles '16px Arial', '12px "Times New Roman"', etc.
  function extractFamily(fontStr: string): string | null {
    const m = fontStr.match(/(?:px|em|rem|pt|%)\s+['"]?(.+?)['"]?\s*$/)
    return m ? m[1].trim().toLowerCase() : null
  }

  Object.defineProperty(CanvasRenderingContext2D.prototype, 'font', {
    get: fontDesc.get,
    set(value: string) {
      if (!reported) {
        const now = Date.now()
        if (now - windowStart > 5000) {
          fontsSeen = new Set()
          windowStart = now
        }

        const family = extractFamily(value)
        if (family) {
          fontsSeen.add(family)
          if (fontsSeen.size > 15) {
            reported = true
            window.dispatchEvent(
              new CustomEvent('eidolon-probe', {
                detail: {
                  type: 'font',
                  detail:
                    `Font enumeration fingerprinting detected — ${fontsSeen.size} unique font families ` +
                    'probed via canvas.font within 5 seconds. Installed fonts are identified by comparing ' +
                    'text rendering widths across font families.',
                },
              })
            )
          }
        }
      }
      return origSet.call(this, value)
    },
    configurable: true,
    enumerable: fontDesc.enumerable,
  })
}
