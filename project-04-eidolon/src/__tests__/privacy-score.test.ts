import { computePrivacyScore } from '../shared/privacy-score'
import { TabData } from '../shared/types'

function makeTab(overrides: Partial<TabData> = {}): TabData {
  return {
    url: 'https://example.com',
    title: 'Example',
    blocked: [],
    fingerprintProbes: [],
    webrtcBlocked: false,
    canvasSpoofed: false,
    lastUpdated: Date.now(),
    ...overrides,
  }
}

function makeBlocked(domain: string, category: TabData['blocked'][0]['category']): TabData['blocked'][0] {
  return {
    url: `https://${domain}/track`,
    type: 'script',
    reason: 'tracker',
    timestamp: Date.now(),
    domain,
    category,
  }
}

describe('computePrivacyScore', () => {
  test('returns score 100 and Minimal Risk for a clean tab', () => {
    const ps = computePrivacyScore(makeTab())
    expect(ps.score).toBe(100)
    expect(ps.label).toBe('Minimal Risk')
    expect(ps.color).toBe('#00d4aa')
    expect(ps.probesDetected).toHaveLength(0)
    expect(Object.keys(ps.categoryBreakdown)).toHaveLength(0)
  })

  test('deducts based on unique blocked domains, not request count', () => {
    // Same domain blocked twice — should count as 1 unique domain
    const tab = makeTab({
      blocked: [
        makeBlocked('hotjar.com', 'session-replay'),
        makeBlocked('hotjar.com', 'session-replay'),
      ],
    })
    const ps = computePrivacyScore(tab)
    expect(ps.categoryBreakdown['session-replay']).toBe(1)
    // 1 unique domain × 7 points = 7 deducted → score 93
    expect(ps.score).toBe(93)
  })

  test('deducts correctly for multiple categories', () => {
    const tab = makeTab({
      blocked: [
        makeBlocked('hotjar.com',          'session-replay'),      // 7 pts
        makeBlocked('google-analytics.com', 'behavioral-analytics'), // 4 pts
        makeBlocked('doubleclick.net',      'ad-network'),           // 2 pts
      ],
    })
    const ps = computePrivacyScore(tab)
    expect(ps.score).toBe(100 - 7 - 4 - 2)  // 87
    expect(ps.label).toBe('Minimal Risk')
  })

  test('fraud-detection carries highest per-domain weight', () => {
    const tab = makeTab({
      blocked: [makeBlocked('threatmetrix.com', 'fraud-detection')],
    })
    const ps = computePrivacyScore(tab)
    expect(ps.score).toBe(90)  // 100 - 10
  })

  test('caps deductions per category', () => {
    // 10 unique session-replay domains: 10 × 7 = 70 pts uncapped
    // Cap for session-replay is 21 → score should be 100 - 21 = 79
    const blocked = Array.from({ length: 10 }, (_, i) =>
      makeBlocked(`replay${i}.com`, 'session-replay')
    )
    const tab = makeTab({ blocked })
    const ps = computePrivacyScore(tab)
    expect(ps.score).toBe(100 - 21)
  })

  test('deducts for fingerprint probes', () => {
    const tab = makeTab({
      fingerprintProbes: [
        { type: 'audio',    detail: 'audio probe', timestamp: Date.now() },
        { type: 'webgl',    detail: 'webgl probe', timestamp: Date.now() },
      ],
    })
    const ps = computePrivacyScore(tab)
    expect(ps.probesDetected).toContain('audio')
    expect(ps.probesDetected).toContain('webgl')
    expect(ps.score).toBe(100 - 10 - 8)  // 82
    expect(ps.label).toBe('Low Risk')
  })

  test('deduplicates probe types — multiple audio probes count as one', () => {
    const tab = makeTab({
      fingerprintProbes: [
        { type: 'audio', detail: 'first', timestamp: Date.now() },
        { type: 'audio', detail: 'second', timestamp: Date.now() },
      ],
    })
    const ps = computePrivacyScore(tab)
    expect(ps.probesDetected).toHaveLength(1)
    expect(ps.score).toBe(100 - 10)  // 90
  })

  test('score floors at 0', () => {
    // Pile on every category with max domains + all 4 probe types
    const blocked = [
      ...Array.from({ length: 5 }, (_, i) => makeBlocked(`fd${i}.com`, 'fraud-detection')),
      ...Array.from({ length: 5 }, (_, i) => makeBlocked(`db${i}.com`, 'data-broker')),
      ...Array.from({ length: 5 }, (_, i) => makeBlocked(`sr${i}.com`, 'session-replay')),
      ...Array.from({ length: 5 }, (_, i) => makeBlocked(`st${i}.com`, 'social-tracking')),
      ...Array.from({ length: 5 }, (_, i) => makeBlocked(`ba${i}.com`, 'behavioral-analytics')),
      ...Array.from({ length: 5 }, (_, i) => makeBlocked(`ad${i}.com`, 'ad-network')),
    ]
    const probes = (['audio', 'webgl', 'font', 'hardware'] as const).map((type) => ({
      type, detail: '', timestamp: Date.now(),
    }))
    const ps = computePrivacyScore(makeTab({ blocked, fingerprintProbes: probes }))
    expect(ps.score).toBeGreaterThanOrEqual(0)
    expect(ps.score).toBeLessThan(20)
    expect(ps.label).toBe('Severe Risk')
    expect(ps.color).toBe('#f56565')
  })

  test('score labels map to correct thresholds', () => {
    // Clean tab → 100 → Minimal Risk
    expect(computePrivacyScore(makeTab()).label).toBe('Minimal Risk')

    // 1 fraud-detection domain = 10pts → score 90 → Minimal Risk
    expect(computePrivacyScore(makeTab({
      blocked: [makeBlocked('threatmetrix.com', 'fraud-detection')],
    })).label).toBe('Minimal Risk')

    // 2 fraud + 2 data-broker = 20+16 = 36pts → score 64 → Moderate Risk
    expect(computePrivacyScore(makeTab({
      blocked: [
        makeBlocked('threatmetrix.com', 'fraud-detection'),
        makeBlocked('kount.net',         'fraud-detection'),
        makeBlocked('bluekai.com',        'data-broker'),
        makeBlocked('krxd.net',           'data-broker'),
      ],
    })).label).toBe('Moderate Risk')

    // Use the floors-at-0 case to assert Severe Risk label
    const heavyBlocked = [
      ...Array.from({ length: 5 }, (_, i) => makeBlocked(`fd${i}.com`, 'fraud-detection')),
      ...Array.from({ length: 5 }, (_, i) => makeBlocked(`db${i}.com`, 'data-broker')),
      ...Array.from({ length: 5 }, (_, i) => makeBlocked(`sr${i}.com`, 'session-replay')),
      ...Array.from({ length: 5 }, (_, i) => makeBlocked(`st${i}.com`, 'social-tracking')),
      ...Array.from({ length: 5 }, (_, i) => makeBlocked(`ba${i}.com`, 'behavioral-analytics')),
    ]
    const heavyProbes = (['audio', 'webgl', 'font', 'hardware'] as const).map((type) => ({
      type, detail: '', timestamp: Date.now(),
    }))
    const heavy = computePrivacyScore(makeTab({ blocked: heavyBlocked, fingerprintProbes: heavyProbes }))
    expect(heavy.label).toBe('Severe Risk')
  })

  test('categoryBreakdown counts unique domains per category', () => {
    const tab = makeTab({
      blocked: [
        makeBlocked('hotjar.com',    'session-replay'),
        makeBlocked('fullstory.com', 'session-replay'),
        makeBlocked('doubleclick.net', 'ad-network'),
      ],
    })
    const ps = computePrivacyScore(tab)
    expect(ps.categoryBreakdown['session-replay']).toBe(2)
    expect(ps.categoryBreakdown['ad-network']).toBe(1)
    expect(ps.categoryBreakdown['behavioral-analytics']).toBeUndefined()
  })
})
