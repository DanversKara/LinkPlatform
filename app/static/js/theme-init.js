/* Theme pre-script: runs synchronously in <head> to avoid a theme flash.
   Kept as an external file (not inline) so it passes the
   Content-Security-Policy (script-src 'self'). Default: dark. */
(function () {
  try {
    var t = localStorage.getItem("lp-theme");
    if (t !== "light" && t !== "dark") t = "dark";
    document.documentElement.dataset.theme = t;
  } catch (e) {
    document.documentElement.dataset.theme = "dark";
  }
})();
/* Mark JS-capable pages early so progressive-enhancement CSS applies before first paint. */
document.documentElement.classList.add("js");
