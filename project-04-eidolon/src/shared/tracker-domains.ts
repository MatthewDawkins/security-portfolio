// Curated list of known tracker/ad domains.
// Subdomains are matched automatically — only root domains needed here.
export const TRACKER_DOMAINS = new Set<string>([
  // Google Analytics & Ads
  'google-analytics.com',
  'googletagmanager.com',
  'googletagservices.com',
  'doubleclick.net',
  'googlesyndication.com',
  'googleadservices.com',
  'adservice.google.com',
  'pagead2.googlesyndication.com',
  'stats.g.doubleclick.net',

  // Facebook / Meta
  'connect.facebook.net',
  'graph.facebook.com',
  'an.facebook.com',
  'pixel.facebook.com',
  'tr.facebook.com',

  // Twitter / X
  'analytics.twitter.com',
  'static.ads-twitter.com',
  'ads.twitter.com',
  'syndication.twitter.com',
  't.co',

  // LinkedIn
  'snap.licdn.com',
  'platform.linkedin.com',
  'ads.linkedin.com',
  'bizographics.com',

  // Amazon Ads
  'amazon-adsystem.com',
  'aax.amazon-adsystem.com',
  'fls-na.amazon.com',
  'adsystem.amazon.com',

  // Microsoft / Bing
  'bat.bing.com',
  'clarity.ms',
  'ads.microsoft.com',
  'c.bing.com',

  // Adobe Analytics / Marketing Cloud
  'omtrdc.net',
  'demdex.net',
  'adobedtm.com',
  '2o7.net',
  'adobedc.net',
  'omniture.com',
  'tt.omtrdc.net',

  // Hotjar
  'hotjar.com',
  'static.hotjar.com',
  'script.hotjar.com',
  'insights.hotjar.com',

  // Mixpanel
  'api.mixpanel.com',
  'cdn.mixpanel.com',

  // Amplitude
  'api.amplitude.com',
  'cdn.amplitude.com',
  'analytics.amplitude.com',

  // Segment
  'cdn.segment.com',
  'api.segment.io',
  'cdn.segment.io',

  // Heap
  'heapanalytics.com',
  'cdn.heapanalytics.com',

  // FullStory
  'fullstory.com',
  'rs.fullstory.com',
  'edge.fullstory.com',

  // Intercom
  'js.intercomcdn.com',
  'api.intercom.io',
  'widget.intercom.io',
  'nexus-websocket-a.intercom.io',

  // HubSpot
  'js.hs-analytics.net',
  'js.hs-scripts.com',
  'track.hubspot.com',
  'forms.hsforms.com',
  'cta-service-cms2.hubspot.com',

  // Pardot / Salesforce
  'pi.pardot.com',
  'go.pardot.com',

  // Marketo
  'munchkin.marketo.net',
  'app.marketo.com',

  // Quantcast
  'quantserve.com',
  'pixel.quantserve.com',

  // AppNexus / Xandr
  'adnxs.com',
  'ib.adnxs.com',

  // Criteo
  'dis.criteo.com',
  'static.criteo.net',
  'gum.criteo.com',
  'sslwidget.criteo.com',
  'bidder.criteo.com',

  // Outbrain
  'widgets.outbrain.com',
  'log.outbrain.com',
  'amplify.outbrain.com',

  // Taboola
  'cdn.taboola.com',
  'trc.taboola.com',
  'log.taboola.com',
  'nr-data.taboola.com',

  // Yandex Metrica
  'mc.yandex.ru',
  'mc.yandex.com',

  // Baidu Analytics
  'hm.baidu.com',

  // TikTok
  'analytics.tiktok.com',
  'ads-api.tiktok.com',
  'log.tiktokv.com',
  'ad.tiktok.com',

  // Snapchat
  'tr.snapchat.com',
  'sc-static.net',

  // Pinterest
  'log.pinterest.com',
  'ct.pinterest.com',
  'ads.pinterest.com',
  'trk.pinterest.com',

  // Reddit
  'alb.reddit.com',
  'pixel.reddit.com',
  'redd.it',

  // Nielsen
  'imrworldwide.com',
  'secure-dcr.imrworldwide.com',
  'cdn-gl.imrworldwide.com',

  // comScore
  'scorecardresearch.com',
  'sb.scorecardresearch.com',
  'pixel.scorecardresearch.com',
  'beacon.scorecardresearch.com',

  // Chartbeat
  'static.chartbeat.com',
  'ping.chartbeat.net',

  // Parse.ly
  'srv.pixel.parsely.com',
  'pixel.parsely.com',
  'api.parsely.com',

  // New Relic (browser agent)
  'bam.nr-data.net',
  'js-agent.newrelic.com',
  'nr-data.net',

  // AddThis
  's7.addthis.com',
  'm.addthis.com',
  'addthis.com',

  // ShareThis
  'w.sharethis.com',
  'platform-api.sharethis.com',

  // Disqus
  'a.disquscdn.com',
  'disqus.com',
  'disqusads.com',

  // DoubleVerify
  'cdn.doubleverify.com',
  'pub.doubleverify.com',
  'rtb.doubleverify.com',

  // Integral Ad Science
  'pixel.adsafeprotected.com',
  'fw.adsafeprotected.com',

  // Moat
  'tags.moatads.com',
  'z.moatads.com',

  // The Trade Desk
  'match.adsrvr.org',
  'insight.adsrvr.org',
  'adsrvr.org',

  // MediaMath
  'pixel.mathtag.com',
  'bh.contextweb.com',
  'mathtag.com',

  // Pubmatic
  'ads.pubmatic.com',
  'image.pubmatic.com',
  'simage2.pubmatic.com',

  // OpenX
  'us-u.openx.net',
  'openx.net',

  // Rubicon / Magnite
  'fastlane.rubiconproject.com',
  'beacon.rubiconproject.com',
  'rubiconproject.com',

  // Index Exchange
  'js-sec.indexww.com',
  'r.casalemedia.com',
  'casalemedia.com',

  // Sovrn
  'ap.lijit.com',
  'beacon.lijit.com',

  // Lucky Orange
  'd.luckyorange.net',
  'cs.luckyorange.net',

  // Mouseflow
  'cdn.mouseflow.com',
  'mouseflow.com',

  // LogRocket
  'cdn.lr-ingest.io',
  'r.lr-ingest.io',

  // Qualtrics
  'siteintercept.qualtrics.com',
  'qualtrics.com',

  // Optimizely
  'cdn.optimizely.com',
  'logx.optimizely.com',

  // VWO
  'dev.visualwebsiteoptimizer.com',
  'visualwebsiteoptimizer.com',

  // Crazy Egg
  'script.crazyegg.com',

  // LiveRamp
  'idsync.rlcdn.com',
  'rlcdn.com',

  // Oracle / BlueKai DMP
  'bluekai.com',
  'bkrtx.com',
  'nexac.com',

  // Krux / Salesforce DMP
  'krxd.net',

  // BidSwitch
  'bidswitch.net',

  // Smart AdServer
  'smartadserver.com',
  'sskzlv.com',

  // ShareThrough
  'sharethrough.com',

  // TripleLift
  'triplelift.com',
  '3lift.com',

  // Sonobi
  'sonobi.com',

  // District M
  'districtm.io',

  // EMX Digital
  'emxdgt.com',

  // 33Across
  '33across.com',
  'tynt.com',

  // Conversant / Epsilon
  'conversantmedia.com',
  'epsilon.com',

  // AdRoll
  'adroll.com',
  'd.adroll.com',

  // Yieldmo
  'yieldmo.com',

  // Kargo
  'kargo.com',

  // SpotX
  'spotx.tv',
  'spotxchange.com',

  // FreeWheel
  'freewheel.tv',
  'adtechfwd.com',

  // Teads
  'teads.tv',
  'teads.com',

  // Nativo
  'nativo.com',
  'postrelease.com',

  // Sizmek
  'serving-sys.com',
  'mediamind.com',

  // Exponential (Tribal Fusion)
  'exponential.com',
  'tribalfusion.com',

  // Conversant / ValueClick
  'valueclick.com',
  'fastclick.net',

  // Undertone
  'undertone.com',

  // GumGum
  'gumgum.com',

  // Lotame
  'crwdcntrl.net',
  'lotame.com',

  // LiveIntent
  'liadm.com',
  'liveintent.com',

  // SessionCam
  'sessioncam.com',

  // ClickTale
  'clicktale.net',
  'clicktale.com',

  // Pendo
  'pendo.io',
  'cdn.pendo.io',

  // Appcues
  'appcues.com',
  'fast.appcues.com',

  // WalkMe
  'walkme.com',
  'cdn.walkme.com',

  // Drift / Driftt
  'drift.com',
  'driftt.com',
  'js.driftt.com',

  // Klaviyo
  'klaviyo.com',
  'static.klaviyo.com',

  // Braze / Appboy
  'braze.com',
  'appboy.com',
  'iad.appboy.com',

  // OneSignal
  'onesignal.com',
  'cdn.onesignal.com',

  // Iterable
  'iterable.com',

  // Sailthru
  'sailthru.com',

  // Threat Metrix / LexisNexis
  'threatmetrix.com',
  'h.online-metrix.net',

  // Kount
  'kount.net',

  // Sift
  'sift.com',
  'siftscience.com',

  // Adform
  'adform.net',
  'track.adform.net',

  // MediaNet
  'media.net',

  // Yahoo / Verizon Media
  'yahoo.com',
  'yimg.com',
  'advertising.yahoo.com',

  // Zemanta
  'zemanta.com',

  // Bidtellect
  'bidtellect.com',

  // Amobee
  'amobee.com',
  'turn.com',
  'tribalfusion.com',

  // Pulsepoint
  'pulsepoint.com',
  'contextweb.com',

  // Xaxis
  'xaxis.com',

  // Dstillery
  'dstillery.com',
  'media6degrees.com',

  // Eyeota
  'eyeota.net',

  // Bombora
  'bombora.com',

  // Dataxu
  'dataxu.com',
])

/**
 * Returns true if the given hostname (or any parent domain) is a known tracker.
 */
export function isTrackerDomain(hostname: string): boolean {
  if (TRACKER_DOMAINS.has(hostname)) return true

  // Walk up subdomains: e.g. "foo.bar.google-analytics.com" → check "bar.google-analytics.com", "google-analytics.com"
  const parts = hostname.split('.')
  for (let i = 1; i < parts.length - 1; i++) {
    if (TRACKER_DOMAINS.has(parts.slice(i).join('.'))) return true
  }

  return false
}
