// WebRTC IP leak blocker — injected into MAIN world via dynamic content script registration.
// No chrome.* APIs available. Registered/unregistered by the background based on settings.
// Forces relay-only ICE transport so STUN cannot expose the user's real local/public IP.

if (typeof RTCPeerConnection !== 'undefined') {
  const NativeRTC = RTCPeerConnection

  function SafeRTCPeerConnection(this: RTCPeerConnection, config?: RTCConfiguration) {
    const safe: RTCConfiguration = {
      ...(config ?? {}),
      iceTransportPolicy: 'relay',
      iceServers: (config?.iceServers ?? []).filter((s) => {
        const urls = Array.isArray(s.urls) ? s.urls : [s.urls]
        return urls.every((u) => typeof u === 'string' && u.startsWith('turn:'))
      }),
    }
    return new NativeRTC(safe)
  }

  SafeRTCPeerConnection.prototype = NativeRTC.prototype

  Object.defineProperty(window, 'RTCPeerConnection', {
    value: SafeRTCPeerConnection,
    writable: true,
    configurable: true,
  })
}
