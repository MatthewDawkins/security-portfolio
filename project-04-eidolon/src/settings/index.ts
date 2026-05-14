import { Settings, DEFAULT_SETTINGS } from '../shared/types'

function sendMessage<T>(message: object): Promise<T> {
  return new Promise((resolve) => chrome.runtime.sendMessage(message, resolve))
}

const SETTING_IDS: Array<keyof Settings> = [
  'blockTrackers',
  'spoofCanvas',
  'blockWebRTC',
  'detectAudioFingerprint',
  'detectWebGLFingerprint',
  'detectFontEnumeration',
  'detectHardwareProbe',
]

async function load() {
  const response = await sendMessage<{ data: Settings }>({ type: 'GET_SETTINGS' })
  const settings: Settings = { ...DEFAULT_SETTINGS, ...(response?.data ?? {}) }

  for (const id of SETTING_IDS) {
    const el = document.getElementById(id) as HTMLInputElement | null
    if (el) el.checked = settings[id] as boolean
  }
}

async function save() {
  const settings: Partial<Settings> = {}

  for (const id of SETTING_IDS) {
    const el = document.getElementById(id) as HTMLInputElement | null
    if (el) (settings as Record<string, boolean>)[id] = el.checked
  }

  await sendMessage({ type: 'SAVE_SETTINGS', settings: { ...DEFAULT_SETTINGS, ...settings } })

  const bar = document.getElementById('status-bar')!
  bar.classList.remove('saving')
  void bar.offsetWidth
  bar.classList.add('saving')
}

for (const id of SETTING_IDS) {
  document.getElementById(id)?.addEventListener('change', save)
}

document.getElementById('reload-btn')!.addEventListener('click', () => {
  chrome.tabs.query({}, (tabs) => {
    for (const tab of tabs) {
      if (tab.id != null && !tab.url?.startsWith('chrome://') && !tab.url?.startsWith('chrome-extension://')) {
        chrome.tabs.reload(tab.id)
      }
    }
  })
})

load()
