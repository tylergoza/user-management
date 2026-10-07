import { Controller } from "@hotwired/stimulus"

// Shows the element (an "you're offline" banner) while the device is offline.
export default class extends Controller {
  connect() {
    this.update = () => (this.element.hidden = navigator.onLine)
    window.addEventListener("online", this.update)
    window.addEventListener("offline", this.update)
    this.update()
  }

  disconnect() {
    window.removeEventListener("online", this.update)
    window.removeEventListener("offline", this.update)
  }
}
