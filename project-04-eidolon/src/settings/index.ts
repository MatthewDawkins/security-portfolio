import { Settings, DEFAULT_SETTINGS } from '../shared/types'

function sendMessage<T>(message: object): Promise<T> {
  return new Promise((resolve) => chrome.runtime.sendMessage(message, resolve))
}

async function load() {
  const response = await sendMessage<{ data: Settings }>({ type: 'GET_SETTINGS' })
  const settings: Settings = response?.data ?? { ...DEFAULT_SETTINGS }

  ;(document.getElementById('blockTrackers') as HTMLInputElement).checked = settings.blockTrackers
  ;(document.getElementById('spoofCanvas')   as HTMLInputElement).checked = settings.spoofCanvas
  ;(document.getElementById('blockWebRTC')   as HTMLInputElement).checked = settings.blockWebRTC
}

async function save() {
  const settings: Settings = {
    blockTrackers: (document.getElementById('blockTrackers') as HTMLInputElement).checked,
    spoofCanvas:   (document.getElementById('spoofCanvas')   as HTMLInputElement).checked,
    blockWebRTC:   (document.getElementById('blockWebRTC')   as HTMLInputElement).checked,
  }

  await sendMessage({ type: 'SAVE_SETTINGS', settings })

  // Brief visual confirmation
  const bar = document.getElementById('status-bar')!
  bar.classList.remove('saving')
  void bar.offsetWidth // force reflow to restart animation
  bar.classList.add('saving')
}

document.getElementById('blockTrackers')!.addEventListener('change', save)
document.getElementById('spoofCanvas')!.addEventListener('change', save)
document.getElementById('blockWebRTC')!.addEventListener('change', save)

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
