export interface BlockedRequest {
  url: string
  type: string
  reason: 'tracker' | 'fingerprint-domain'
  timestamp: number
  domain: string
}

export interface TabData {
  url: string
  title: string
  blocked: BlockedRequest[]
  webrtcBlocked: boolean
  canvasSpoofed: boolean
  lastUpdated: number
}

export interface ExtensionState {
  enabled: boolean
  tabs: Record<number, TabData>
  totalBlocked: number
}

export interface Settings {
  blockTrackers: boolean
  spoofCanvas: boolean
  blockWebRTC: boolean
}

export const DEFAULT_SETTINGS: Settings = {
  blockTrackers: true,
  spoofCanvas: true,
  blockWebRTC: true,
}

export type Message =
  | { type: 'GET_STATE' }
  | { type: 'GET_TAB_DATA'; tabId: number }
  | { type: 'TOGGLE_ENABLED' }
  | { type: 'GET_SETTINGS' }
  | { type: 'SAVE_SETTINGS'; settings: Settings }
  | { type: 'CANVAS_SPOOFED' }
  | { type: 'WEBRTC_BLOCKED' }
  | { type: 'OPEN_DASHBOARD' }
  | { type: 'BLOCKED'; tabId: number; blocked: BlockedRequest }
