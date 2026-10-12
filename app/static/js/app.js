/* ============================================================
   LinkPlatform v12 — app.js (vanilla, no dependencies)
   ============================================================ */
(function () {
  "use strict";

  /* ---------- Theme (default: dark) ---------- */
  function applyTheme() {
    var t = null;
    try { t = localStorage.getItem("lp-theme"); } catch (e) { /* storage unavailable */ }
    if (t !== "light" && t !== "dark") t = "dark";
    document.documentElement.dataset.theme = t;
    document.querySelectorAll("[data-theme-toggle]").forEach(function (btn) {
      btn.setAttribute("aria-pressed", t === "light" ? "true" : "false");
    });
  }
  document.addEventListener("click", function (e) {
    var btn = e.target.closest("[data-theme-toggle]");
    if (!btn) return;
    var next = document.documentElement.dataset.theme === "light" ? "dark" : "light";
    try { localStorage.setItem("lp-theme", next); } catch (e) { /* ignore */ }
    applyTheme();
  });
  applyTheme();

  /* ---------- CSRF token ---------- */
  function csrfToken() {
    var m = document.querySelector('meta[name="csrf"]');
    return m ? m.getAttribute("content") : "";
  }

  /* ---------- Toast ---------- */
  var toastWrap = document.querySelector(".toast-wrap");
  function toast(msg, type) {
    type = type || "info";
    var icon = type === "success" ? "check" : type === "error" ? "alert" : "info";
    if (!toastWrap) {
      toastWrap = document.createElement("div");
      toastWrap.className = "toast-wrap";
      toastWrap.setAttribute("aria-live", "polite");
      document.body.appendChild(toastWrap);
    }
    var el = document.createElement("div");
    el.className = "toast toast-" + type;
    el.innerHTML = '<svg aria-hidden="true"><use href="#i-' + icon + '"/></svg><span></span>';
    el.querySelector("span").textContent = msg;
    toastWrap.appendChild(el);
    setTimeout(function () {
      el.classList.add("out");
      setTimeout(function () { el.remove(); }, 320);
    }, 4000);
  }
  window.lpToast = toast;

  // Auto-dismiss server-rendered toasts
  document.querySelectorAll(".toast-wrap .toast[data-autodismiss]").forEach(function (el) {
    setTimeout(function () {
      el.classList.add("out");
      setTimeout(function () { el.remove(); }, 320);
    }, 4000);
  });

  /* ---------- fetch API wrapper ---------- */
  async function api(method, url, data) {
    var opts = {
      method: method,
      headers: {
        "x-csrf-token": csrfToken(),
        "Accept": "application/json"
      },
      credentials: "same-origin"
    };
    if (data !== undefined && data !== null) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(data);
    }
    var res = await fetch(url, opts);
    var body = null;
    try { body = await res.json(); } catch (e) { /* non-JSON response */ }
    if (!res.ok) {
      var err = new Error((body && body.detail) || ("Request failed (" + res.status + ")"));
      err.status = res.status;
      err.body = body;
      throw err;
    }
    return body;
  }
  window.lpApi = api;

  /* ---------- Copy buttons ---------- */
  document.addEventListener("click", function (e) {
    var btn = e.target.closest("[data-copy]");
    if (!btn) return;
    e.preventDefault();
    var text = btn.getAttribute("data-copy");
    if (text === null || text === undefined) return;
    function done() { toast("Copied to clipboard", "success"); }
    function fail() { toast("Copy failed — select and copy manually", "error"); }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, fail);
    } else {
      var ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand("copy") ? done() : fail(); } catch (err) { fail(); }
      ta.remove();
    }
  });

  /* ---------- Auto-submit selects (CSP-safe replacement for onchange) ---------- */
  document.addEventListener("change", function (e) {
    var el = e.target.closest("select[data-autosubmit]");
    if (el && el.form) el.form.submit();
  });

  /* ---------- Easter egg: the desktop "menu" button is a fidget spinner ----------
     On desktop the nav is always visible, so the hamburger has nothing to do.
     Spin it 5 times for a surprise; every 5 spins after that, a new quote. */
  (function () {
    var btn = document.querySelector("[data-nav-toggle]");
    if (!btn) return;
    var desktop = window.matchMedia("(min-width: 901px)");
    var spins = 0, bubble = null, hideTimer = null;
    var quotes = [
      "Spin responsibly.",
      "Studies show 9 out of 10 links are shortened faster while spinning.",
      "You are now legally a professional fidgeter.",
      "This button has no job. You gave it purpose.",
      "Somewhere, a 2017 kid just felt a disturbance in the force.",
      "Achievement unlocked: Productivity? Never heard of her.",
      "The spinner spins. The deadline approaches. Balance.",
      "Fun fact: this counter is the most-used feature on the site.",
      "Bearing status: frictionless. Your free time: also frictionless.",
      "Keep going. The links can wait.",
      "Certified fidget spinner. Batteries not included.",
      "If you stop now, the spinner wins."
    ];
    var lastQuote = -1;
    function pick() {
      var i;
      do { i = Math.floor(Math.random() * quotes.length); } while (quotes.length > 1 && i === lastQuote);
      lastQuote = i;
      return quotes[i];
    }
    function show(title, text, sticky) {
      if (!bubble) {
        bubble = document.createElement("div");
        bubble.className = "spin-bubble";
        bubble.setAttribute("role", "status");
        bubble.setAttribute("aria-live", "polite");
        document.body.appendChild(bubble);
      }
      var r = btn.getBoundingClientRect();
      bubble.style.top = (r.bottom + 10 + window.scrollY) + "px";
      bubble.style.left = (r.left + window.scrollX) + "px";
      bubble.innerHTML = "<strong></strong><span></span>";
      bubble.querySelector("strong").textContent = title;
      bubble.querySelector("span").textContent = text || "";
      bubble.classList.remove("out");
      bubble.classList.add("in");
      clearTimeout(hideTimer);
      hideTimer = setTimeout(function () { bubble.classList.add("out"); }, sticky ? 5000 : 1600);
    }
    btn.addEventListener("click", function () {
      if (!desktop.matches) return;              // mobile: normal menu toggle
      spins += 1;
      btn.classList.remove("spin-go");
      void btn.offsetWidth;                      // restart the animation
      btn.classList.add("spin-go");
      btn.style.setProperty("--spin-speed", Math.max(0.25, 0.9 - spins * 0.03) + "s");
      if (spins === 5) {
        show("Fun fidget spinner, huh…", "Spins: 5 — keep going?", true);
      } else if (spins > 5 && spins % 5 === 0) {
        show("Spins: " + spins, pick(), true);
      } else if (spins > 5) {
        show("Spins: " + spins, "", false);
      }
    });
  })();

  /* ---------- Delete confirmations ---------- */
  document.addEventListener("submit", function (e) {
    var form = e.target.closest("form[data-confirm]");
    if (!form) return;
    var msg = form.getAttribute("data-confirm") || "Are you sure?";
    if (!window.confirm(msg)) e.preventDefault();
  });

  /* ---------- Table live filter ---------- */
  document.querySelectorAll("input[data-filter-table]").forEach(function (input) {
    var selector = input.getAttribute("data-filter-table");
    var table = document.querySelector(selector);
    if (!table) return;
    input.addEventListener("input", function () {
      var q = input.value.trim().toLowerCase();
      var rows = table.querySelectorAll("tbody tr");
      var visible = 0;
      rows.forEach(function (row) {
        var hit = !q || row.textContent.toLowerCase().indexOf(q) !== -1;
        row.style.display = hit ? "" : "none";
        if (hit) visible++;
      });
      var empty = table.parentElement.querySelector("[data-filter-empty]");
      if (empty) empty.classList.toggle("hidden", visible !== 0);
    });
  });

  /* ---------- Mobile nav toggle ---------- */
  document.addEventListener("click", function (e) {
    var btn = e.target.closest("[data-nav-toggle]");
    if (!btn) return;
    var nav = document.querySelector(".nav-links");
    if (!nav) return;
    var open = nav.classList.toggle("open");
    btn.setAttribute("aria-expanded", open ? "true" : "false");
  });

  /* ---------- Password strength (length only) ---------- */
  document.querySelectorAll('input[type="password"][data-pw-strength]').forEach(function (input) {
    var meter = document.createElement("div");
    meter.className = "pw-meter";
    meter.setAttribute("aria-hidden", "true");
    var bar = document.createElement("span");
    meter.appendChild(bar);
    var hint = document.createElement("div");
    hint.className = "hint";
    input.insertAdjacentElement("afterend", meter);
    meter.insertAdjacentElement("afterend", hint);
    function update() {
      var len = input.value.length;
      var pct = Math.min(100, Math.round((len / 16) * 100));
      bar.style.width = pct + "%";
      if (len === 0) { bar.style.background = "transparent"; hint.textContent = ""; return; }
      if (len < 8) { bar.style.background = "var(--danger)"; hint.textContent = "Too short — use at least 8 characters."; }
      else if (len < 12) { bar.style.background = "var(--warning)"; hint.textContent = "Okay — 12+ characters is stronger."; }
      else { bar.style.background = "var(--success)"; hint.textContent = "Strong length."; }
    }
    input.addEventListener("input", update);
    update();
  });

  /* ---------- Close user menu on outside click / Escape ---------- */
  document.addEventListener("click", function (e) {
    document.querySelectorAll("details.user-menu[open]").forEach(function (d) {
      if (!d.contains(e.target)) d.removeAttribute("open");
    });
  });
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape") {
      document.querySelectorAll("details.user-menu[open]").forEach(function (d) { d.removeAttribute("open"); });
      document.querySelectorAll(".nav-links.open").forEach(function (n) { n.classList.remove("open"); });
    }
  });
})();
