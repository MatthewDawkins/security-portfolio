// ── Threat taxonomy ─────────────────────────────────────────────────────────

export type ThreatCategory =
  | 'ad-network'
  | 'behavioral-analytics'
  | 'session-replay'
  | 'social-tracking'
  | 'data-broker'
  | 'marketing-automation'
  | 'ab-testing'
  | 'telemetry'
  | 'fraud-detection'

export interface CategoryMeta {
  label: string
  description: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  color: string
}

export const CATEGORY_META: Record<ThreatCategory, CategoryMeta> = {
  'fraud-detection': {
    label: 'Fraud Detection',
    description:
      'Device fingerprinting systems that build persistent identity tokens from hardware characteristics. Functionally indistinguishable from surveillance infrastructure.',
    severity: 'critical',
    color: '#f56565',
  },
  'data-broker': {
    label: 'Data Broker',
    description:
      'Data management platforms and identity resolution networks that aggregate your browsing activity across thousands of sites to build and sell behavioral profiles.',
    severity: 'high',
    color: '#fc8181',
  },
  'session-replay': {
    label: 'Session Replay',
    description:
      'Tools that record every mouse movement, click, scroll, and keystroke — reconstructing exact video replays of your browsing session.',
    severity: 'high',
    color: '#f6ad55',
  },
  'social-tracking': {
    label: 'Social Tracking',
    description:
      'Social media pixels that correlate your activity across sites with your social network identity, enabling cross-site behavioral attribution.',
    severity: 'high',
    color: '#ed8936',
  },
  'behavioral-analytics': {
    label: 'Behavioral Analytics',
    description:
      'Product analytics platforms that track every user action, event, and conversion funnel step to build detailed behavioral engagement profiles.',
    severity: 'medium',
    color: '#68d391',
  },
  'marketing-automation': {
    label: 'Marketing Automation',
    description:
      'CRM and email marketing systems that tie your web activity to your email address for targeted outreach, lead scoring, and conversion tracking.',
    severity: 'medium',
    color: '#63b3ed',
  },
  'ab-testing': {
    label: 'A/B Testing',
    description:
      'Experimentation and optimization platforms that track which content variants you see and measure behavioral responses to influence product decisions.',
    severity: 'low',
    color: '#76e4f7',
  },
  'ad-network': {
    label: 'Ad Network',
    description:
      'Programmatic advertising infrastructure — DSPs, SSPs, ad exchanges, and verification layers — that bid on your attention in real-time auctions.',
    severity: 'medium',
    color: '#b794f4',
  },
  'telemetry': {
    label: 'Telemetry',
    description:
      'Performance monitoring and audience measurement systems collecting page metrics, engagement signals, and audience statistics.',
    severity: 'low',
    color: '#90cdf4',
  },
}

// ── Fingerprint probe types ──────────────────────────────────────────────────

export type FingerprintProbeType = 'audio' | 'webgl' | 'font' | 'hardware'

export interface FingerprintProbe {
  type: FingerprintProbeType
  detail: string
  timestamp: number
}

// ── Core data structures ─────────────────────────────────────────────────────

export interface BlockedRequest {
  url: string
  type: string
  reason: 'tracker'
  timestamp: number
  domain: string
  category: ThreatCategory
}

export interface TabData {
  url: string
  title: string
  blocked: BlockedRequest[]
  fingerprintProbes: FingerprintProbe[]
  webrtcBlocked: boolean
  canvasSpoofed: boolean
  lastUpdated: number
}

export interface ExtensionState {
  enabled: boolean
  tabs: Record<number, TabData>
  totalBlocked: number
}

// ── Privacy score ────────────────────────────────────────────────────────────

export interface PrivacyScore {
  score: number
  label: string
  color: string
  categoryBreakdown: Partial<Record<ThreatCategory, number>>
  probesDetected: FingerprintProbeType[]
}

// ── Settings ─────────────────────────────────────────────────────────────────

export interface Settings {
  blockTrackers: boolean
  spoofCanvas: boolean
  blockWebRTC: boolean
  detectAudioFingerprint: boolean
  detectWebGLFingerprint: boolean
  detectFontEnumeration: boolean
  detectHardwareProbe: boolean
}

export const DEFAULT_SETTINGS: Settings = {
  blockTrackers: true,
  spoofCanvas: true,
  blockWebRTC: true,
  detectAudioFingerprint: true,
  detectWebGLFingerprint: true,
  detectFontEnumeration: true,
  detectHardwareProbe: true,
}

// ── Message bus ───────────────────────────────────────────────────────────────

export type Message =
  | { type: 'GET_STATE' }
  | { type: 'GET_TAB_DATA'; tabId: number }
  | { type: 'TOGGLE_ENABLED' }
  | { type: 'GET_SETTINGS' }
  | { type: 'SAVE_SETTINGS'; settings: Settings }
  | { type: 'CANVAS_SPOOFED' }
  | { type: 'WEBRTC_BLOCKED' }
  | { type: 'FINGERPRINT_PROBE'; probe: FingerprintProbe }
  | { type: 'OPEN_DASHBOARD' }
  | { type: 'BLOCKED'; tabId: number; blocked: BlockedRequest }
