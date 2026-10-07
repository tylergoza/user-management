// Stimulus autoloader — no build step, no Hotwire/Turbo, no importmap-rails.
//
// Watches the DOM for data-controller attributes and lazily imports the
// matching controller module the first time an identifier is seen, then
// registers it with the Stimulus application. Elements added later (or
// whose data-controller attribute changes) are picked up automatically.
//
// Naming convention (same as the old stimulus-loading / Rails convention):
//
//   data-controller="nav"             -> controllers/nav_controller.js
//   data-controller="task-filter"     -> controllers/task_filter_controller.js
//   data-controller="pwa--install"    -> controllers/pwa/install_controller.js
//
// i.e. "--" becomes a directory separator and "-" becomes "_". Each module
// must `export default` a Controller subclass.
//
// Usage:
//   import { Application } from "@hotwired/stimulus"
//   import { autoload } from "./stimulus_autoloader.js"
//   const app = Application.start()
//   autoload(app, { baseURL: new URL("./controllers/", import.meta.url) })

export function identifierToPath(identifier) {
  return identifier
    .split("--")
    .map((part) => part.replace(/-/g, "_"))
    .join("/") + "_controller.js"
}

export function autoload(application, options = {}) {
  const {
    root = document.documentElement,
    baseURL = new URL("./controllers/", import.meta.url),
    // Appended as ?v= so a deploy busts cached controller modules.
    version = new URL(import.meta.url).searchParams.get("v"),
    // Controllers to load immediately even if not yet on the page.
    eager = [],
  } = options

  const attribute = application.schema.controllerAttribute // "data-controller"
  const loading = new Map() // identifier -> Promise
  const failed = new Set()

  function urlFor(identifier) {
    const url = new URL(identifierToPath(identifier), baseURL)
    if (version) url.searchParams.set("v", version)
    return url.href
  }

  function isRegistered(identifier) {
    return application.router.modulesByIdentifier.has(identifier)
  }

  function load(identifier) {
    if (!identifier || failed.has(identifier)) return Promise.resolve()
    if (isRegistered(identifier)) return Promise.resolve()
    if (loading.has(identifier)) return loading.get(identifier)

    const promise = import(urlFor(identifier))
      .then((module) => {
        if (!module.default) {
          throw new Error(`${identifierToPath(identifier)} has no default export`)
        }
        if (!isRegistered(identifier)) application.register(identifier, module.default)
      })
      .catch((error) => {
        failed.add(identifier)
        console.error(`[stimulus-autoloader] Failed to load controller "${identifier}"`, error)
      })
      .finally(() => loading.delete(identifier))

    loading.set(identifier, promise)
    return promise
  }

  function identifiersIn(element) {
    const ids = new Set()
    const collect = (el) => {
      const value = el.getAttribute(attribute)
      if (value) value.split(/\s+/).forEach((id) => id && ids.add(id))
    }
    if (element.nodeType !== Node.ELEMENT_NODE) return ids
    if (element.hasAttribute(attribute)) collect(element)
    element.querySelectorAll(`[${attribute}]`).forEach(collect)
    return ids
  }

  function scan(element) {
    return Promise.all([...identifiersIn(element)].map(load))
  }

  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      if (mutation.type === "attributes") {
        scan(mutation.target)
      } else {
        mutation.addedNodes.forEach((node) => scan(node))
      }
    }
  })

  observer.observe(root, {
    childList: true,
    subtree: true,
    attributes: true,
    attributeFilter: [attribute],
  })

  eager.forEach(load)
  const ready = scan(root)

  return {
    /** Resolves once controllers present at startup are registered. */
    ready,
    /** Manually load a controller by identifier. */
    load,
    /** Stop watching the DOM. */
    disconnect: () => observer.disconnect(),
  }
}
