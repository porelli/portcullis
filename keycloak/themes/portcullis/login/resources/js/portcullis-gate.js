// Portcullis sign-in gate (theme.properties `scripts`, run in <head> before
// the page paints). The drop (css/portcullis.css) plays on the first sign-in
// page of a sign-in in this tab and again on a reload of any page; the pages
// after it within 10 minutes (the password form after the passkey page, an
// error, the needs-stronger page) show the gate already down: the class
// pc-gate-still on <html>. The "Let
// through" page (the rise) ends the sign-in: the next one drops again.
// Only sessionStorage, per tab; nothing leaves the browser. No storage
// (private mode, blocked): the drop plays on every page.
(function () {
  "use strict";
  var KEY = "portcullis.gate.dropped";
  var WINDOW_MS = 10 * 60 * 1000;
  try {
    var now = Date.now();
    var last = Number(window.sessionStorage.getItem(KEY)) || 0;
    // A reload of the same page replays the drop (Navigation Timing's
    // type "reload"); only the later steps of a sign-in (and, through the
    // stylesheet, error pages) show it already down.
    var nav = window.performance && window.performance.getEntriesByType
      ? window.performance.getEntriesByType("navigation")[0] : null;
    var reload = !!(nav && nav.type === "reload");
    if (!reload && now - last >= 0 && now - last < WINDOW_MS) {
      document.documentElement.classList.add("pc-gate-still");
    }
    window.sessionStorage.setItem(KEY, String(now));
    document.addEventListener("DOMContentLoaded", function () {
      if (document.body && document.body.getAttribute("data-page-id") === "login-portcullis-let-through") {
        window.sessionStorage.removeItem(KEY);
      }
    });
  } catch (e) {
    // storage unavailable: the drop plays
  }
})();
