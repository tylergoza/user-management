import { Controller } from "@hotwired/stimulus"

// "Install app" button. Chrome/Edge/Android fire beforeinstallprompt, which
// we stash and replay on click. iOS Safari has no prompt API, so there we
// show instructions for Share → Add to Home Screen instead.
//
// Loaded via the namespaced identifier "pwa--install".
let deferredPrompt = null
window.addEventListener("beforeinstallprompt", (event) => {
  event.preventDefault()
  deferredPrompt = event
  document.dispatchEvent(new CustomEvent("pwa:installable"))
})

export default class extends Controller {
  connect() {
    this.onInstallable = () => this.#refresh()
    document.addEventListener("pwa:installable", this.onInstallable)
    window.addEventListener("appinstalled", this.onInstallable)
    this.#refresh()
  }

  disconnect() {
    document.removeEventListener("pwa:installable", this.onInstallable)
    window.removeEventListener("appinstalled", this.onInstallable)
  }

  async prompt() {
    if (deferredPrompt) {
      deferredPrompt.prompt()
      await deferredPrompt.userChoice
      deferredPrompt = null
      this.#refresh()
    } else if (this.#isIOS()) {
      alert("To install: tap the Share button in Safari, then choose \"Add to Home Screen\".")
    }
  }

  #refresh() {
    const standalone = window.matchMedia("(display-mode: standalone)").matches || navigator.standalone
    this.element.hidden = standalone || !(deferredPrompt || this.#isIOS())
  }

  #isIOS() {
    return /iphone|ipad|ipod/i.test(navigator.userAgent) && !window.MSStream
  }
}
