/*
 * One namespace, two browsers.
 *
 * Firefox exposes the promise-returning `browser` namespace. Chrome exposes `chrome`, and only
 * recent Chrome aliases it as `browser` as well. Two differences matter to this add-on, both of
 * them measured on real builds (Chrome 113 has neither, Chrome 148 has both):
 *
 *  1. `browser.*` — on Chrome without the alias, every other file's `browser.storage.local.get()`
 *     would throw a ReferenceError. The alias is installed here where it is missing.
 *  2. A `runtime.onMessage` listener that *returns a Promise* — Firefox's form, and the one
 *     background.js and content.js are written in. Chrome accepted it only recently; before that
 *     a listener returning a promise was ignored and the sender got `undefined` (no error, just a
 *     silent no-answer). Where the promise form is not native, promise-returning listeners are
 *     bridged onto `sendResponse` + `return true`, the one form every MV3 engine implements.
 *
 * This file does nothing in a real Firefox extension context (detected by `getBrowserInfo`), and
 * nothing at all outside an extension (the test harness runs the add-on in a plain page, where
 * `chrome.runtime.id` does not exist).
 */
(function (global) {
  "use strict";

  const api = global.chrome;
  const inExtension = Boolean(api && api.runtime && api.runtime.id);
  if (!inExtension) return;

  const isGecko = typeof api.runtime.getBrowserInfo === "function";
  if (isGecko) return;

  if (!global.browser) {
    try {
      global.browser = api;
    } catch (error) {
      // A frozen global (some embedders): the caller reports a normal API failure.
    }
  }

  const messages = api.runtime.onMessage;
  if (!messages || typeof messages.addListener !== "function") return;
  const addListener = messages.addListener.bind(messages);

  messages.addListener = function (listener) {
    return addListener(function (message, sender, sendResponse) {
      const answer = listener(message, sender, sendResponse);
      if (!answer || typeof answer.then !== "function") return answer;
      // The caller's promise is resolved by sendResponse; the empty Persian-side error text leaves
      // the wording to the UI's own fallback rather than leaking an English JS message into it.
      answer.then(
        function (value) {
          try {
            sendResponse(value);
          } catch (error) {
            /* the channel is gone (tab closed, page navigated): nothing left to answer */
          }
        },
        function () {
          try {
            sendResponse({ ok: false, error: { code: "ERROR", text: "" } });
          } catch (error) {
            /* same */
          }
        }
      );
      return true; // keep the message channel open for the asynchronous answer
    });
  };
})(globalThis);
