import { Application } from "@hotwired/stimulus"
import { autoload } from "stimulus-autoloader"

const application = Application.start()
application.debug = false
window.Stimulus = application

// Controllers are loaded on demand from ./controllers/ as they appear in
// the DOM. See stimulus_autoloader.js for the naming convention.
autoload(application, {
  baseURL: new URL("./controllers/", import.meta.url),
  version: new URL(import.meta.url).searchParams.get("v"),
})

// Offline support / installability.
if ("serviceWorker" in navigator) {
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("/sw.js", { scope: "/" }).catch((error) => {
      console.warn("Service worker registration failed", error)
    })
  })
}
