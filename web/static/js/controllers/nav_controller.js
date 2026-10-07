import { Controller } from "@hotwired/stimulus"

// Collapsible main navigation on small screens.
export default class extends Controller {
  static targets = ["menu", "toggle"]

  toggle() {
    this.open = !this.element.classList.contains("is-open")
    this.#apply()
  }

  close() {
    if (!this.open) return
    this.open = false
    this.#apply()
  }

  #apply() {
    this.element.classList.toggle("is-open", this.open)
    this.toggleTarget.setAttribute("aria-expanded", String(this.open))
  }
}
