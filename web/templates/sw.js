// Service worker. Served from /sw.js by the Go server, which injects the
// asset version and precache list below. A new asset version means a new
// cache; old caches are removed on activate.
//
// Unlike the other apps, no pages are kept for offline use: account pages
// shouldn't linger on a device, and signing in (/login, /authorize and the
// redirects back to an app) must always reach the server. Pages go straight
// to the network, with the offline page only when there is no network.
const VERSION = "__VERSION__"
const STATIC_CACHE = `um-static-${VERSION}`
const PRECACHE = __PRECACHE__

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(STATIC_CACHE).then((cache) => cache.addAll(PRECACHE)).then(() => self.skipWaiting())
  )
})

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(
        keys.filter((key) => key.startsWith("um-static-") && key !== STATIC_CACHE).map((key) => caches.delete(key))
      ))
      .then(() => self.clients.claim())
  )
})

self.addEventListener("fetch", (event) => {
  const request = event.request
  const url = new URL(request.url)
  if (url.origin !== self.location.origin || request.method !== "GET") return

  if (url.pathname.startsWith("/static/")) {
    event.respondWith(cacheFirst(request))
  } else if (request.mode === "navigate") {
    event.respondWith(networkOrOffline(request))
  }
})

async function cacheFirst(request) {
  const cache = await caches.open(STATIC_CACHE)
  const cached = await cache.match(request)
  if (cached) return cached
  const response = await fetch(request)
  if (response.ok) cache.put(request, response.clone())
  return response
}

// Redirects (including to an app on another site) pass straight through.
async function networkOrOffline(request) {
  try {
    return await fetch(request)
  } catch (error) {
    return (
      (await caches.match("/offline")) ||
      new Response("You are offline.", { status: 503, headers: { "Content-Type": "text/plain" } })
    )
  }
}
