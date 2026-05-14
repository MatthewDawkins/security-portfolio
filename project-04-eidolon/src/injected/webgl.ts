// WebGL fingerprint detector — injected into MAIN world.
// No chrome.* APIs available here. Communicates detections via CustomEvent
// which content.js (isolated world) listens for and forwards to background.
//
// Detection: fingerprinters read RENDERER and VENDOR strings (hardware name,
// driver version) via getParameter(). The WEBGL_debug_renderer_info extension
// exposes unmasked strings that identify the exact GPU model across sites.

const FINGERPRINT_PARAMS: Record<number, string> = {
  0x1F00: 'VENDOR',
  0x1F01: 'RENDERER',
  0x1F02: 'VERSION',
  0x8B8D: 'SHADING_LANGUAGE_VERSION',
  0x9245: 'UNMASKED_VENDOR_WEBGL',
  0x9246: 'UNMASKED_RENDERER_WEBGL',
}

function patchContext(proto: WebGLRenderingContext) {
  const orig = (proto as WebGLRenderingContext & { getParameter: (p: number) => unknown }).getParameter

  ;(proto as WebGLRenderingContext & { getParameter: (p: number) => unknown }).getParameter =
    function (this: WebGLRenderingContext, pname: number) {
      if (FINGERPRINT_PARAMS[pname] !== undefined) {
        window.dispatchEvent(
          new CustomEvent('eidolon-probe', {
            detail: {
              type: 'webgl',
              detail:
                `WebGL hardware string enumeration detected — getParameter(${FINGERPRINT_PARAMS[pname]}). ` +
                'Fingerprinters read GPU renderer/vendor strings to identify hardware across sessions.',
            },
          })
        )
      }
      return orig.call(this, pname)
    }
}

if (typeof WebGLRenderingContext !== 'undefined') {
  patchContext(WebGLRenderingContext.prototype as unknown as WebGLRenderingContext)
}
if (typeof WebGL2RenderingContext !== 'undefined') {
  patchContext(WebGL2RenderingContext.prototype as unknown as WebGLRenderingContext)
}
