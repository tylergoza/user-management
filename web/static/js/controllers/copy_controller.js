import { Controller } from "@hotwired/stimulus"

// Copies a value to the clipboard, and says so on the button for a moment.
//   <div data-controller="copy">
//     <code data-copy-target="source">value</code>
//     <button type="button" data-action="copy#copy" data-copy-target="button">Copy</button>
//   </div>
// Where the clipboard isn't available (plain http on another machine), it
// selects the value instead so it can be copied by hand.
export default class extends Controller {
  static targets = ["source", "button"]

  async copy() {
    const text = this.sourceTarget.textContent.trim()
    try {
      await navigator.clipboard.writeText(text)
      this.say("Copied")
    } catch {
      const range = document.createRange()
      range.selectNodeContents(this.sourceTarget)
      const sel = window.getSelection()
      sel.removeAllRanges()
      sel.addRange(range)
      this.say("Selected: press Ctrl+C")
    }
  }

  say(label) {
    if (!this.hasButtonTarget) return
    const button = this.buttonTarget
    button.dataset.label ||= button.textContent
    button.textContent = label
    clearTimeout(this.timer)
    this.timer = setTimeout(() => { button.textContent = button.dataset.label }, 2000)
  }

  disconnect() {
    clearTimeout(this.timer)
  }
}
