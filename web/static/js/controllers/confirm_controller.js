import { Controller } from "@hotwired/stimulus"

// Asks for confirmation before a form submits.
//   <form data-controller="confirm" data-confirm-message-value="Sure?"
//         data-action="submit->confirm#check">
export default class extends Controller {
  static values = { message: { type: String, default: "Are you sure?" } }

  check(event) {
    if (!window.confirm(this.messageValue)) event.preventDefault()
  }
}
