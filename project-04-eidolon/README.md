# Eidolon — Browser Privacy Extension

> A production-quality Chrome extension built with TypeScript and Manifest V3 that blocks trackers, spoofs canvas fingerprints, and prevents WebRTC IP leaks — with a live per-tab dashboard and granular settings.

---

## What It Does

Modern websites deploy a layered tracking stack: network-level requests to ad platforms, browser fingerprinting via the Canvas API, and WebRTC STUN probes that leak your real IP even through a VPN. Eidolon addresses all three independently:

| Protection | Mechanism | Effect |
|---|---|---|
| **Tracker blocking** | `declarativeNetRequest` rules (237 domains) | Third-party requests to ad networks, analytics, and data brokers are blocked at the network layer before they reach the page |
| **Canvas fingerprint spoofing** | Per-session LCG noise injected into `toDataURL` and `getImageData` | Each browser session produces a cryptographically distinct canvas fingerprint, preventing cross-session linkage |
| **WebRTC IP leak blocking** | `RTCPeerConnection` override forcing `iceTransportPolicy: 'relay'` | STUN candidates that expose the real local/public IP are suppressed; only TURN relays are permitted |

---

## Technical Implementation

### Architecture

```
┌─────────────────────────────────────────────────────┐
│  background.js  (MV3 Service Worker)                 │
│  • Manages state in chrome.storage                   │
│  • Dynamically registers canvas.js / webrtc.js       │
│    into MAIN world via chrome.scripting              │
│  • Syncs declarativeNetRequest rulesets              │
│  • Counts blocked requests per tab                   │
└────────────┬────────────────────────┬────────────────┘
             │                        │
   ┌─────────▼──────────┐   ┌────────▼────────────────┐
   │  content.js         │   │  canvas.js / webrtc.js   │
   │  (Isolated world)   │   │  (MAIN world, CSP-safe)  │
   │  • Notifies bg of   │   │  • Patches Canvas APIs   │
   │    active protections│  │  • Patches RTCPeerConn   │
   └────────────────────┘   └─────────────────────────┘
```

### Key Technical Decisions

**CSP bypass via dynamic MAIN world injection** — The canvas and WebRTC overrides need to run in the page's JavaScript context before any page scripts execute. A naive `<script src="...">` tag injection is blocked by strict Content Security Policies on many sites (news, finance, social). The solution uses `chrome.scripting.registerContentScripts` with `world: "MAIN"` from the background service worker, which the browser injects directly — bypassing CSP entirely, guaranteed to run at `document_start`.

**Dynamic registration for per-feature settings** — Rather than injecting a script and checking runtime flags, each protection is its own registered content script. Toggling a feature calls `chrome.scripting.unregisterContentScripts`, so the script simply never runs on the next page load. No async storage reads in page context, no race conditions.

**Declarative network blocking** — MV3 removed `webRequestBlocking`. Tracker blocking is implemented as a single `declarativeNetRequest` rule with 237 domains in `requestDomains`, covering all resource types. This rule is dynamically enabled/disabled via `updateEnabledRulesets`, allowing the master toggle and per-feature settings to take effect immediately without reloading the extension.

**Session-unique canvas noise** — The LCG (Linear Congruential Generator) uses a per-page-load random seed (`Math.random() | 0`). It applies ±1 delta to 8 deterministic-but-session-unique pixel positions across both `toDataURL` and `getImageData`. The result is visually identical output with a cryptographically distinct hash per session.

### Stack

- **Language:** TypeScript (strict)
- **Bundler:** Webpack 5
- **APIs:** Chrome Extension MV3 — `declarativeNetRequest`, `scripting`, `webRequest`, `storage`, `tabs`
- **Runtime:** Chrome Extension Service Worker

---

## Features

- **Popup** — Real-time per-tab blocked request count, canvas/WebRTC status, live tracker feed
- **Dashboard** — Full request log across all open tabs, sortable by block count, expandable per-tab detail
- **Settings page** — Independent toggles for tracker blocking, canvas spoofing, and WebRTC protection with immediate effect
- **237-domain blocklist** — Covers Google, Meta, TikTok, Adobe, trade desk platforms, DMPs, CDPs, session replay tools, A/B testing platforms, and data brokers

---

## Installation (Load Unpacked)

1. Clone this repo
2. In Chrome, go to `chrome://extensions`
3. Enable **Developer mode**
4. Click **Load unpacked** and select the `dist/` folder inside this project

To rebuild from source:
```bash
npm install
npm run build
```

---

## Verified Results

| Test | Result |
|---|---|
| EFF Cover Your Tracks | Strong protection — ads and invisible trackers blocked |
| browserleaks.com/canvas | Canvas fingerprint changes on every page load |
| browserleaks.com/webrtc | No WebRTC IP leak detected |
| CNN.com | 5+ tracker/ad domains blocked per page load |

---

## Skills Demonstrated

- Chrome Extension development (Manifest V3)
- TypeScript
- Browser security internals (CSP, isolated worlds, MAIN world injection)
- API interception and prototype patching
- Fingerprinting techniques and mitigations
- Webpack bundling and build tooling
- Async/event-driven architecture (service workers, message passing)
