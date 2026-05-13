// Generates public/rules.json for Chrome MV3 declarativeNetRequest.
// Run via: node scripts/generate-rules.js
// Or automatically as part of npm run build via webpack.config.js.

const fs = require('fs')
const path = require('path')

const TRACKER_DOMAINS = [
  // Google
  'google-analytics.com', 'googletagmanager.com', 'googletagservices.com',
  'doubleclick.net', 'googlesyndication.com', 'googleadservices.com',
  'adservice.google.com', 'pagead2.googlesyndication.com', 'stats.g.doubleclick.net',
  // Facebook / Meta
  'connect.facebook.net', 'graph.facebook.com', 'an.facebook.com',
  'pixel.facebook.com', 'tr.facebook.com',
  // Twitter / X
  'analytics.twitter.com', 'static.ads-twitter.com', 'ads.twitter.com',
  'syndication.twitter.com', 't.co',
  // LinkedIn
  'snap.licdn.com', 'platform.linkedin.com', 'ads.linkedin.com', 'bizographics.com',
  // Amazon
  'amazon-adsystem.com', 'aax.amazon-adsystem.com', 'fls-na.amazon.com', 'adsystem.amazon.com',
  // Microsoft / Bing
  'bat.bing.com', 'clarity.ms', 'ads.microsoft.com', 'c.bing.com',
  // Adobe
  'omtrdc.net', 'demdex.net', 'adobedtm.com', '2o7.net', 'adobedc.net', 'omniture.com', 'tt.omtrdc.net',
  // Hotjar
  'hotjar.com', 'static.hotjar.com', 'script.hotjar.com', 'insights.hotjar.com',
  // Mixpanel
  'api.mixpanel.com', 'cdn.mixpanel.com',
  // Amplitude
  'api.amplitude.com', 'cdn.amplitude.com', 'analytics.amplitude.com',
  // Segment
  'cdn.segment.com', 'api.segment.io', 'cdn.segment.io',
  // Heap
  'heapanalytics.com', 'cdn.heapanalytics.com',
  // FullStory
  'fullstory.com', 'rs.fullstory.com', 'edge.fullstory.com',
  // Intercom
  'js.intercomcdn.com', 'api.intercom.io', 'widget.intercom.io',
  // HubSpot
  'js.hs-analytics.net', 'js.hs-scripts.com', 'track.hubspot.com',
  'forms.hsforms.com', 'cta-service-cms2.hubspot.com',
  // Pardot
  'pi.pardot.com', 'go.pardot.com',
  // Marketo
  'munchkin.marketo.net', 'app.marketo.com',
  // Quantcast
  'quantserve.com', 'pixel.quantserve.com',
  // AppNexus / Xandr
  'adnxs.com', 'ib.adnxs.com',
  // Criteo
  'dis.criteo.com', 'static.criteo.net', 'gum.criteo.com',
  'sslwidget.criteo.com', 'bidder.criteo.com',
  // Outbrain
  'widgets.outbrain.com', 'log.outbrain.com', 'amplify.outbrain.com',
  // Taboola
  'cdn.taboola.com', 'trc.taboola.com', 'log.taboola.com',
  // Yandex
  'mc.yandex.ru', 'mc.yandex.com',
  // Baidu
  'hm.baidu.com',
  // TikTok
  'analytics.tiktok.com', 'ads-api.tiktok.com', 'log.tiktokv.com', 'ad.tiktok.com',
  // Snapchat
  'tr.snapchat.com', 'sc-static.net',
  // Pinterest
  'log.pinterest.com', 'ct.pinterest.com', 'ads.pinterest.com', 'trk.pinterest.com',
  // Reddit
  'alb.reddit.com', 'pixel.reddit.com',
  // Nielsen
  'imrworldwide.com', 'secure-dcr.imrworldwide.com', 'cdn-gl.imrworldwide.com',
  // comScore
  'scorecardresearch.com', 'sb.scorecardresearch.com', 'pixel.scorecardresearch.com',
  // Chartbeat
  'static.chartbeat.com', 'ping.chartbeat.net',
  // Parse.ly
  'srv.pixel.parsely.com', 'pixel.parsely.com', 'api.parsely.com',
  // New Relic
  'bam.nr-data.net', 'js-agent.newrelic.com', 'nr-data.net',
  // AddThis
  's7.addthis.com', 'm.addthis.com', 'addthis.com',
  // ShareThis
  'w.sharethis.com', 'platform-api.sharethis.com',
  // Disqus
  'a.disquscdn.com', 'disqus.com', 'disqusads.com',
  // DoubleVerify
  'cdn.doubleverify.com', 'pub.doubleverify.com', 'rtb.doubleverify.com',
  // IAS
  'pixel.adsafeprotected.com', 'fw.adsafeprotected.com',
  // Moat
  'tags.moatads.com', 'z.moatads.com',
  // The Trade Desk
  'match.adsrvr.org', 'insight.adsrvr.org', 'adsrvr.org',
  // MediaMath
  'pixel.mathtag.com', 'bh.contextweb.com', 'mathtag.com',
  // Pubmatic
  'ads.pubmatic.com', 'image.pubmatic.com', 'simage2.pubmatic.com',
  // OpenX
  'us-u.openx.net', 'openx.net',
  // Magnite / Rubicon
  'fastlane.rubiconproject.com', 'beacon.rubiconproject.com', 'rubiconproject.com',
  // Index Exchange
  'js-sec.indexww.com', 'r.casalemedia.com', 'casalemedia.com',
  // Sovrn
  'ap.lijit.com', 'beacon.lijit.com',
  // Lucky Orange
  'd.luckyorange.net', 'cs.luckyorange.net',
  // Mouseflow
  'cdn.mouseflow.com', 'mouseflow.com',
  // LogRocket
  'cdn.lr-ingest.io', 'r.lr-ingest.io',
  // Qualtrics
  'siteintercept.qualtrics.com',
  // Optimizely
  'cdn.optimizely.com', 'logx.optimizely.com',
  // VWO
  'dev.visualwebsiteoptimizer.com', 'visualwebsiteoptimizer.com',
  // Crazy Egg
  'script.crazyegg.com',
  // LiveRamp
  'idsync.rlcdn.com', 'rlcdn.com',
  // Oracle BlueKai
  'bluekai.com', 'bkrtx.com', 'nexac.com',
  // Krux / Salesforce DMP
  'krxd.net',
  // BidSwitch
  'bidswitch.net',
  // Smart AdServer
  'smartadserver.com',
  // ShareThrough
  'sharethrough.com',
  // TripleLift
  'triplelift.com', '3lift.com',
  // Sonobi
  'sonobi.com',
  // District M
  'districtm.io',
  // EMX Digital
  'emxdgt.com',
  // 33Across
  '33across.com', 'tynt.com',
  // Conversant / Epsilon
  'conversantmedia.com', 'epsilon.com',
  // AdRoll
  'adroll.com', 'd.adroll.com',
  // Yieldmo
  'yieldmo.com',
  // Kargo
  'kargo.com',
  // SpotX
  'spotx.tv', 'spotxchange.com',
  // FreeWheel
  'freewheel.tv', 'adtechfwd.com',
  // Teads
  'teads.tv', 'teads.com',
  // Nativo
  'nativo.com', 'postrelease.com',
  // Sizmek
  'serving-sys.com',
  // Exponential
  'exponential.com', 'tribalfusion.com',
  // ValueClick
  'valueclick.com', 'fastclick.net',
  // Undertone
  'undertone.com',
  // GumGum
  'gumgum.com',
  // Lotame
  'crwdcntrl.net', 'lotame.com',
  // LiveIntent
  'liadm.com', 'liveintent.com',
  // SessionCam
  'sessioncam.com',
  // ClickTale
  'clicktale.net', 'clicktale.com',
  // Pendo
  'pendo.io', 'cdn.pendo.io',
  // Appcues
  'appcues.com', 'fast.appcues.com',
  // WalkMe
  'walkme.com', 'cdn.walkme.com',
  // Drift
  'drift.com', 'driftt.com', 'js.driftt.com',
  // Klaviyo
  'klaviyo.com', 'static.klaviyo.com',
  // Braze / Appboy
  'braze.com', 'appboy.com', 'iad.appboy.com',
  // OneSignal
  'onesignal.com', 'cdn.onesignal.com',
  // Iterable
  'iterable.com',
  // Sailthru
  'sailthru.com',
  // ThreatMetrix
  'threatmetrix.com', 'h.online-metrix.net',
  // Kount
  'kount.net',
  // Sift
  'sift.com', 'siftscience.com',
  // Adform
  'adform.net', 'track.adform.net',
  // Media.net
  'media.net',
  // Yahoo / Verizon
  'advertising.yahoo.com',
  // Amobee / Turn
  'amobee.com', 'turn.com',
  // Pulsepoint
  'pulsepoint.com', 'contextweb.com',
  // Xaxis
  'xaxis.com',
  // Dstillery
  'dstillery.com',
  // Eyeota
  'eyeota.net',
  // Bombora
  'bombora.com',
  // Dataxu
  'dataxu.com',
]

const RESOURCE_TYPES = [
  'script', 'xmlhttprequest', 'image', 'sub_frame',
  'stylesheet', 'font', 'media', 'websocket', 'ping', 'other',
]

const rules = [
  {
    id: 1,
    priority: 1,
    action: { type: 'block' },
    condition: {
      requestDomains: TRACKER_DOMAINS,
      domainType: 'thirdParty',
      resourceTypes: RESOURCE_TYPES,
    },
  },
]

const outPath = path.join(__dirname, '..', 'public', 'rules.json')
fs.writeFileSync(outPath, JSON.stringify(rules, null, 2))
console.log(`Generated ${outPath} with ${TRACKER_DOMAINS.length} tracker domains.`)
