import { getTrackerCategory, isTrackerDomain } from '../shared/tracker-domains'

describe('isTrackerDomain', () => {
  test('returns true for exact known tracker domains', () => {
    expect(isTrackerDomain('google-analytics.com')).toBe(true)
    expect(isTrackerDomain('hotjar.com')).toBe(true)
    expect(isTrackerDomain('doubleclick.net')).toBe(true)
    expect(isTrackerDomain('connect.facebook.net')).toBe(true)
    expect(isTrackerDomain('threatmetrix.com')).toBe(true)
  })

  test('returns true for subdomains of known tracker domains', () => {
    expect(isTrackerDomain('script.hotjar.com')).toBe(true)
    expect(isTrackerDomain('cdn.heapanalytics.com')).toBe(true)
    expect(isTrackerDomain('stats.g.doubleclick.net')).toBe(true)
    expect(isTrackerDomain('api.segment.io')).toBe(true)
    expect(isTrackerDomain('deep.nested.subdomain.doubleclick.net')).toBe(true)
  })

  test('returns false for legitimate domains', () => {
    expect(isTrackerDomain('google.com')).toBe(false)
    expect(isTrackerDomain('facebook.com')).toBe(false)
    expect(isTrackerDomain('github.com')).toBe(false)
    expect(isTrackerDomain('mieza.ai')).toBe(false)
    expect(isTrackerDomain('cloudflare.com')).toBe(false)
    expect(isTrackerDomain('cdn.jsdelivr.net')).toBe(false)
  })

  test('returns false for empty or nonsense input', () => {
    expect(isTrackerDomain('')).toBe(false)
    expect(isTrackerDomain('localhost')).toBe(false)
    expect(isTrackerDomain('com')).toBe(false)
  })
})

describe('getTrackerCategory', () => {
  test('classifies session replay tools correctly', () => {
    expect(getTrackerCategory('hotjar.com')).toBe('session-replay')
    expect(getTrackerCategory('fullstory.com')).toBe('session-replay')
    expect(getTrackerCategory('mouseflow.com')).toBe('session-replay')
    expect(getTrackerCategory('clarity.ms')).toBe('session-replay')
    expect(getTrackerCategory('sessioncam.com')).toBe('session-replay')
    expect(getTrackerCategory('clicktale.net')).toBe('session-replay')
  })

  test('classifies behavioral analytics tools correctly', () => {
    expect(getTrackerCategory('google-analytics.com')).toBe('behavioral-analytics')
    expect(getTrackerCategory('api.mixpanel.com')).toBe('behavioral-analytics')
    expect(getTrackerCategory('api.amplitude.com')).toBe('behavioral-analytics')
    expect(getTrackerCategory('heapanalytics.com')).toBe('behavioral-analytics')
    expect(getTrackerCategory('pendo.io')).toBe('behavioral-analytics')
  })

  test('classifies social tracking correctly', () => {
    expect(getTrackerCategory('connect.facebook.net')).toBe('social-tracking')
    expect(getTrackerCategory('analytics.twitter.com')).toBe('social-tracking')
    expect(getTrackerCategory('snap.licdn.com')).toBe('social-tracking')
    expect(getTrackerCategory('tr.snapchat.com')).toBe('social-tracking')
    expect(getTrackerCategory('analytics.tiktok.com')).toBe('social-tracking')
  })

  test('classifies data brokers correctly', () => {
    expect(getTrackerCategory('demdex.net')).toBe('data-broker')
    expect(getTrackerCategory('bluekai.com')).toBe('data-broker')
    expect(getTrackerCategory('krxd.net')).toBe('data-broker')
    expect(getTrackerCategory('rlcdn.com')).toBe('data-broker')
    expect(getTrackerCategory('scorecardresearch.com')).toBe('data-broker')
    expect(getTrackerCategory('imrworldwide.com')).toBe('data-broker')
  })

  test('classifies marketing automation correctly', () => {
    expect(getTrackerCategory('track.hubspot.com')).toBe('marketing-automation')
    expect(getTrackerCategory('munchkin.marketo.net')).toBe('marketing-automation')
    expect(getTrackerCategory('klaviyo.com')).toBe('marketing-automation')
    expect(getTrackerCategory('braze.com')).toBe('marketing-automation')
    expect(getTrackerCategory('drift.com')).toBe('marketing-automation')
  })

  test('classifies A/B testing tools correctly', () => {
    expect(getTrackerCategory('cdn.optimizely.com')).toBe('ab-testing')
    expect(getTrackerCategory('visualwebsiteoptimizer.com')).toBe('ab-testing')
    expect(getTrackerCategory('siteintercept.qualtrics.com')).toBe('ab-testing')
  })

  test('classifies fraud detection correctly', () => {
    expect(getTrackerCategory('threatmetrix.com')).toBe('fraud-detection')
    expect(getTrackerCategory('h.online-metrix.net')).toBe('fraud-detection')
    expect(getTrackerCategory('kount.net')).toBe('fraud-detection')
    expect(getTrackerCategory('sift.com')).toBe('fraud-detection')
  })

  test('classifies telemetry correctly', () => {
    expect(getTrackerCategory('bam.nr-data.net')).toBe('telemetry')
    expect(getTrackerCategory('js-agent.newrelic.com')).toBe('telemetry')
    expect(getTrackerCategory('ping.chartbeat.net')).toBe('telemetry')
  })

  test('classifies ad network correctly', () => {
    expect(getTrackerCategory('doubleclick.net')).toBe('ad-network')
    expect(getTrackerCategory('adnxs.com')).toBe('ad-network')
    expect(getTrackerCategory('adsrvr.org')).toBe('ad-network')
    expect(getTrackerCategory('rubiconproject.com')).toBe('ad-network')
    expect(getTrackerCategory('criteo.net')).toBe(null) // root, not subdomains listed
    expect(getTrackerCategory('static.criteo.net')).toBe('ad-network')
  })

  test('returns null for non-tracker domains', () => {
    expect(getTrackerCategory('google.com')).toBe(null)
    expect(getTrackerCategory('mieza.ai')).toBe(null)
    expect(getTrackerCategory('github.com')).toBe(null)
  })

  test('resolves categories through subdomain chain', () => {
    // "deep.subdomain.adsrvr.org" should resolve via "adsrvr.org"
    expect(getTrackerCategory('pixel.match.adsrvr.org')).toBe('ad-network')
    expect(getTrackerCategory('cdn2.static.hotjar.com')).toBe('session-replay')
  })
})
