import { FingerprintProbeType, PrivacyScore, TabData, ThreatCategory } from './types'

// Score deduction per unique blocked domain in each category.
// Capped at 5× per category so one extremely tracker-heavy site can't
// dominate; the overall picture matters more than raw counts.
const CATEGORY_WEIGHT: Record<ThreatCategory, number> = {
  'fraud-detection':      10,
  'data-broker':           8,
  'session-replay':        7,
  'social-tracking':       5,
  'behavioral-analytics':  4,
  'marketing-automation':  3,
  'ab-testing':            2,
  'ad-network':            2,
  'telemetry':             1,
}

const CATEGORY_CAP: Record<ThreatCategory, number> = {
  'fraud-detection':      20,
  'data-broker':          24,
  'session-replay':       21,
  'social-tracking':      20,
  'behavioral-analytics': 16,
  'marketing-automation': 12,
  'ab-testing':            8,
  'ad-network':           18,
  'telemetry':             6,
}

// Score deduction per distinct fingerprint probe type detected.
const PROBE_WEIGHT: Record<FingerprintProbeType, number> = {
  audio:    10,
  webgl:     8,
  font:      6,
  hardware:  5,
}

export function computePrivacyScore(tab: TabData): PrivacyScore {
  let totalDeduction = 0
  const categoryBreakdown: Partial<Record<ThreatCategory, number>> = {}

  // Count unique domains per category
  const domainsByCategory = new Map<ThreatCategory, Set<string>>()
  for (const req of tab.blocked) {
    if (!domainsByCategory.has(req.category)) {
      domainsByCategory.set(req.category, new Set())
    }
    domainsByCategory.get(req.category)!.add(req.domain)
  }

  for (const [cat, domains] of domainsByCategory) {
    const deduction = Math.min(domains.size * CATEGORY_WEIGHT[cat], CATEGORY_CAP[cat])
    totalDeduction += deduction
    categoryBreakdown[cat] = domains.size
  }

  // Fingerprint probe deductions (once per distinct type detected)
  const probesDetected = [...new Set(tab.fingerprintProbes.map((p) => p.type))]
  for (const type of probesDetected) {
    totalDeduction += PROBE_WEIGHT[type]
  }

  const score = Math.max(0, 100 - totalDeduction)

  let label: string
  let color: string
  if (score >= 85) {
    label = 'Minimal Risk'
    color = '#00d4aa'
  } else if (score >= 65) {
    label = 'Low Risk'
    color = '#68d391'
  } else if (score >= 40) {
    label = 'Moderate Risk'
    color = '#f6ad55'
  } else if (score >= 20) {
    label = 'High Risk'
    color = '#fc8181'
  } else {
    label = 'Severe Risk'
    color = '#f56565'
  }

  return { score, label, color, categoryBreakdown, probesDetected }
}
