/* ============================================================
   LinkPlatform — bio-page.js
   Behaviour for public bio pages (/@slug), ported from karas.page:
   seasonal themes, tech header layers, holiday particles, wind
   leaves, share/copy/toast, accessibility toolbar + read-aloud,
   and the editor's live-preview bridge (postMessage).
   External file (not inline) so it passes CSP script-src 'self'.
   ============================================================ */
(function () {
  "use strict";

  var root = document.documentElement;
  var body = document.body;
  var REDUCED = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var DATA = {};
  try { DATA = JSON.parse(document.getElementById("bioPalettes").textContent || "{}"); } catch (e) { DATA = {}; }
  var SEASONS = DATA.seasons || [];
  var DAYS = DATA.days || {};
  var PALETTES = DATA.palettes || {};

  var state = {
    themeId: body.dataset.themeId || "default",
    effects: body.dataset.effects || "auto",
    seasonalTagline: body.dataset.seasonalTagline === "1",
    customPrimary: body.dataset.customPrimary || "",
    current: null
  };
  var binTimers = [];

  function $(id) { return document.getElementById(id); }
  function cssVar(name) { return getComputedStyle(root).getPropertyValue(name).trim(); }

  /* ---------------- Theme ---------------- */
  function seasonNow(d) {
    d = d || new Date();
    var key = String(d.getMonth() + 1).padStart(2, "0") + "-" + String(d.getDate()).padStart(2, "0");
    return DAYS[key] || SEASONS[d.getMonth()] || null;
  }

  function resolveTheme() {
    if (state.themeId === "seasonal") return seasonNow();
    return PALETTES[state.themeId] || PALETTES["default"] || null;
  }

  function applyTheme(t) {
    if (!t) return;
    state.current = t;
    root.style.setProperty("--primary", state.customPrimary || t.primary);
    root.style.setProperty("--secondary", t.secondary);
    root.style.setProperty("--accent", t.accent);
    root.style.setProperty("--bg", t.bg);
    root.style.setProperty("--text", t.text || "#ecf0f1");
    root.style.setProperty("--text-muted", t.muted || "#95a5a6");
    var meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.setAttribute("content", t.bg);

    var p = state.customPrimary || t.primary;
    var glow = $("bgGlow");
    if (glow) {
      glow.style.background =
        "radial-gradient(ellipse at 20% 20%, " + p + "1a 0%, transparent 50%)," +
        "radial-gradient(ellipse at 80% 80%, " + t.secondary + "14 0%, transparent 50%)," +
        "radial-gradient(ellipse at 50% 50%, " + t.accent + "0f 0%, transparent 50%)";
    }
    var lbl = $("themeLabel");
    if (lbl && t.name) lbl.textContent = t.name;

    var bio = $("profileBio");
    if (bio) {
      var original = bio.getAttribute("data-original") || "";
      var text = (state.seasonalTagline && state.themeId === "seasonal" && t.bio) ? t.bio : original;
      bio.textContent = text;
      bio.hidden = !text;
    }
    buildTechLayer("heroLayer", 18, 3);
    buildTechLayer("footerLayer", 8, 2);
    buildHolidayFx(effectFor(t));
  }

  function effectFor(t) {
    if (state.effects === "none") return "";
    if (state.effects === "auto") return state.themeId === "seasonal" ? (t.fx || "") : "";
    return state.effects;
  }

  var previewIdx = -1;
  function previewNextTheme() {
    if (!SEASONS.length) return;
    if (previewIdx < 0) previewIdx = new Date().getMonth();
    previewIdx = (previewIdx + 1) % 12;
    applyTheme(SEASONS[previewIdx]);
    showToast("Preview: " + SEASONS[previewIdx].name);
  }

  /* ---------------- Tech header layer ---------------- */
  function el(tag, cls) { var e = document.createElement(tag); if (cls) e.className = cls; return e; }

  function buildTechLayer(id, binCount, lineCount) {
    var host = $(id);
    if (!host) return;
    host.innerHTML = "";
    if (REDUCED) return;
    var p = cssVar("--primary"), s = cssVar("--secondary"), a = cssVar("--accent");

    host.appendChild(el("div", "tech-grid-bg"));

    var cw = el("div", "circuit-wrap");
    for (var i = 0; i < lineCount; i++) {
      var ln = el("div", "c-line");
      ln.style.top = (15 + i * (65 / lineCount)) + "%";
      ln.style.animationDelay = (i * 1.1) + "s";
      cw.appendChild(ln);
    }
    host.appendChild(cw);

    var dw = el("div", "dot-wrap");
    for (var j = 0; j < 8; j++) {
      var d = el("div", "c-dot");
      d.style.left = (Math.random() * 96) + "%";
      d.style.top = (Math.random() * 90) + "%";
      d.style.animationDelay = (Math.random() * 2.5) + "s";
      dw.appendChild(d);
    }
    host.appendChild(dw);

    // Floating glyphs (icon-font free stand-ins for chip/code/server icons)
    var iw = el("div", "icon-wrap");
    var glyphs = ["</>", "{ }", ">_", "#", "⌁", "◈"];
    var clrs = [p, s, a];
    for (var k = 0; k < 4; k++) {
      var ic = el("span", "c-icon");
      ic.textContent = glyphs[(Math.random() * glyphs.length) | 0];
      ic.style.fontFamily = "'JetBrains Mono', monospace";
      ic.style.fontWeight = "700";
      ic.style.top = (8 + Math.random() * 75) + "%";
      ic.style.left = (5 + Math.random() * 88) + "%";
      ic.style.color = clrs[k % 3];
      ic.style.animationDelay = (Math.random() * 6) + "s";
      iw.appendChild(ic);
    }
    host.appendChild(iw);

    var br = el("div", "bin-rain");
    for (var m = 0; m < binCount; m++) {
      var b = el("span", "bin-d");
      b.textContent = Math.random() > 0.5 ? "1" : "0";
      b.style.left = (Math.random() * 100) + "%";
      b.style.animationDuration = (Math.random() * 3.5 + 2.5) + "s";
      b.style.animationDelay = (Math.random() * 6) + "s";
      b.style.color = Math.random() > 0.5 ? p : s;
      br.appendChild(b);
    }
    host.appendChild(br);
    binTimers.push(setInterval(function () {
      var ds = br.querySelectorAll(".bin-d");
      for (var n = 0; n < ds.length; n++) ds[n].textContent = Math.random() > 0.5 ? "1" : "0";
    }, 1100));

    host.appendChild(el("div", "holo"));
  }

  /* ---------------- Holiday particles ---------------- */
  function buildHolidayFx(type) {
    var c = $("holidayBg");
    if (!c) return;
    c.innerHTML = "";
    if (REDUCED || !type) return;
    var p = cssVar("--primary"), s = cssVar("--secondary");
    function rnd(a, b) { return Math.random() * (b - a) + a; }
    function add(cls, styles, text) {
      var e = el("div", cls);
      if (text) e.textContent = text;
      for (var k in styles) e.style[k] = styles[k];
      c.appendChild(e);
    }
    var FX = {
      snow: function () {
        for (var i = 0; i < 45; i++) {
          var sz = rnd(2, 6);
          add("snow-dot", { width: sz + "px", height: sz + "px", left: rnd(0, 100) + "%", top: -rnd(0, 20) + "%",
            animationDuration: rnd(5, 12) + "s", animationDelay: rnd(0, 7) + "s", opacity: rnd(0.2, 0.8) });
        }
      },
      hearts: function () {
        for (var i = 0; i < 22; i++) add("heart-dot", { left: rnd(0, 100) + "%", fontSize: rnd(9, 23) + "px",
          animationDuration: rnd(4, 9) + "s", animationDelay: rnd(0, 7) + "s", opacity: rnd(0.3, 0.8) }, "♥");
      },
      bats: function () {
        for (var i = 0; i < 14; i++) add("bat-dot", { top: rnd(5, 60) + "%", fontSize: rnd(14, 24) + "px",
          animationDuration: rnd(4, 9) + "s", animationDelay: rnd(0, 9) + "s" }, "🦇");
      },
      confetti: function () {
        var cl = ["#e74c3c", "#3498db", "#f1c40f", "#2ecc71", "#9b59b6", "#e84393"];
        for (var i = 0; i < 55; i++) add("confetti-dot", { left: rnd(0, 100) + "%", width: rnd(4, 12) + "px",
          height: rnd(6, 20) + "px", background: cl[i % cl.length], borderRadius: Math.random() > 0.5 ? "50%" : "2px",
          animationDuration: rnd(3, 7) + "s", animationDelay: rnd(0, 5) + "s" });
      },
      fireflies: function () {
        for (var i = 0; i < 28; i++) add("firefly-dot", { left: rnd(0, 100) + "%", top: rnd(0, 100) + "%",
          background: i % 2 ? s : p, color: i % 2 ? s : p, animationDuration: rnd(2, 5) + "s", animationDelay: rnd(0, 4) + "s" });
      },
      leaves: function () {
        var cl = ["#d35400", "#e67e22", "#c0392b", "#a04000", "#935116"];
        for (var i = 0; i < 28; i++) add("leaf-dot", { left: rnd(0, 100) + "%", background: cl[i % cl.length],
          animationDuration: rnd(4, 9) + "s", animationDelay: rnd(0, 7) + "s", opacity: "0.7" });
      },
      stars: function () {
        var sy = ["★", "✦", "✧", "⋆", "✶"], cl = ["#f1c40f", "#e74c3c", "#3498db", "#ffffff"];
        for (var i = 0; i < 35; i++) add("star-dot", { left: rnd(0, 100) + "%", top: rnd(0, 100) + "%", color: cl[i % cl.length],
          fontSize: rnd(8, 24) + "px", animationDuration: rnd(1, 3) + "s", animationDelay: rnd(0, 3) + "s" }, sy[i % sy.length]);
      },
      petals: function () {
        var cl = ["#ff6b9d", "#ffd166", "#ff85b3", "#ffb347"];
        for (var i = 0; i < 22; i++) add("petal-dot", { left: rnd(0, 100) + "%", background: cl[i % cl.length],
          animationDuration: rnd(4, 9) + "s", animationDelay: rnd(0, 7) + "s", opacity: "0.72" });
      },
      bunnies: function () {
        for (var i = 0; i < 8; i++) add("bunny-dot", { left: rnd(2, 90) + "%", top: rnd(60, 90) + "%", fontSize: rnd(16, 28) + "px",
          animationDuration: rnd(0.7, 1.6) + "s", animationDelay: rnd(0, 2) + "s", opacity: "0.62" }, i % 2 ? "🥚" : "🐰");
      }
    };
    if (FX[type]) FX[type]();
  }

  function buildWindLeaves() {
    var w = $("windLayer");
    if (!w || REDUCED) return;
    w.innerHTML = "";
    for (var i = 0; i < 16; i++) {
      var d = el("span", "wind-leaf");
      d.style.top = (24 + Math.random() * 68) + "%";
      d.style.animationDuration = (7 + Math.random() * 10) + "s";
      d.style.animationDelay = (-Math.random() * 17) + "s";
      d.style.opacity = (0.18 + Math.random() * 0.42).toFixed(2);
      var sz = 6 + Math.random() * 6;
      d.style.width = sz + "px";
      d.style.height = sz + "px";
      if (i % 3 === 0) d.style.background = "var(--secondary)";
      if (i % 5 === 0) d.style.background = "var(--accent)";
      w.appendChild(d);
    }
  }

  /* ---------------- Toast / clipboard / share ---------------- */
  var toastTimer = null;
  function showToast(msg, dur) {
    var t = $("toast");
    if (!t) return;
    t.textContent = msg;
    t.style.opacity = "1";
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { t.style.opacity = "0"; }, dur || 3200);
  }

  function copyText(text, msg) {
    function fallback() {
      var ta = document.createElement("textarea");
      ta.value = text;
      ta.setAttribute("readonly", "");
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      body.appendChild(ta);
      ta.select();
      var ok = false;
      try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
      ta.remove();
      showToast(ok ? msg : "Copy manually: " + text);
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () { showToast(msg); }, fallback);
    } else {
      fallback();
    }
  }

  document.addEventListener("click", function (e) {
    var card = e.target.closest("[data-copy-text]");
    if (card) {
      e.preventDefault();
      copyText(card.getAttribute("data-copy-text"), "Copied to clipboard!");
      return;
    }
    if (e.target.closest("#shareBtn")) {
      var title = $("shareBtn").getAttribute("data-share-title") || document.title;
      var url = location.href.split("?")[0];
      if (navigator.share) {
        navigator.share({ title: title, text: "Check out " + title + "'s links!", url: url }).catch(function () {});
      } else {
        copyText(url, "Link copied to clipboard!");
      }
      return;
    }
  });

  /* ---------------- Misc ---------------- */
  function updateDate() {
    var d = $("dateDisplay");
    if (d) d.textContent = new Date().toLocaleDateString(undefined, { weekday: "long", year: "numeric", month: "long", day: "numeric" });
  }

  function avatarFallback() {
    var img = $("profileAvatar");
    if (!img || img.tagName !== "IMG") return;
    img.addEventListener("error", function () {
      var div = el("div", "avatar-initial");
      div.id = "profileAvatar";
      div.setAttribute("aria-hidden", "true");
      div.textContent = (body.dataset.name || "?").charAt(0).toUpperCase();
      img.replaceWith(div);
    });
  }

  function scheduleMidnight() {
    var now = new Date();
    var next = new Date(now); next.setDate(now.getDate() + 1); next.setHours(0, 0, 5, 0);
    setTimeout(function () {
      if (state.themeId === "seasonal") applyTheme(resolveTheme());
      updateDate();
      scheduleMidnight();
    }, next - now);
  }

  /* ---------------- Editor live preview ---------------- */
  // The bio editor embeds this page in an iframe (?preview=1) and posts
  // unsaved form values here so the preview updates as the user types.
  function onPreviewMessage(e) {
    if (e.origin !== location.origin) return;
    var m = e.data;
    if (!m || m.type !== "lp-bio-preview") return;
    if (typeof m.name === "string") {
      var h = $("profileName"); if (h) h.textContent = m.name || " ";
      body.dataset.name = m.name;
      var av = $("profileAvatar");
      if (av && av.tagName !== "IMG") av.textContent = (m.name || "?").charAt(0).toUpperCase();
    }
    if (typeof m.bio === "string") {
      var b = $("profileBio"); if (b) b.setAttribute("data-original", m.bio);
    }
    if (m.avatar) {
      var cur = $("profileAvatar");
      if (cur) {
        var img = document.createElement("img");
        img.className = "avatar"; img.id = "profileAvatar"; img.alt = ""; img.src = m.avatar;
        cur.replaceWith(img);
      }
    }
    if (typeof m.footer === "string") { var f = $("footerText"); if (f) f.textContent = m.footer; }
    if (m.theme) state.themeId = m.theme;
    if (typeof m.effects === "string") state.effects = m.effects;
    if (typeof m.seasonalTagline === "boolean") state.seasonalTagline = m.seasonalTagline;
    if (typeof m.customPrimary === "string") state.customPrimary = m.customPrimary;
    if (typeof m.scene === "boolean") body.classList.toggle("no-scene", !m.scene);
    if (typeof m.tech === "boolean") body.classList.toggle("no-tech", !m.tech);
    if (m.layout === "grid" || m.layout === "list") {
      body.classList.remove("layout-grid", "layout-list");
      body.classList.add("layout-" + m.layout);
    }
    var toggles = { share: "#shareBtn", report: '.action-row a[href^="/report/"]', date: "#dateDisplay" };
    Object.keys(toggles).forEach(function (k) {
      if (typeof m[k] !== "boolean") return;
      var node = document.querySelector(toggles[k]);
      if (node) node.style.display = m[k] ? "" : "none";
    });
    binTimers.forEach(clearInterval); binTimers = [];
    applyTheme(resolveTheme());
  }

  /* ---------------- Accessibility toolbar ---------------- */
  function initA11y() {
    var toggleBtn = $("a11y-toggle"), panel = $("a11y-panel"), closeBtn = $("a11yClose");
    if (!toggleBtn || !panel) return;
    var KEY = "a11yPrefs";
    var defaults = { fontStep: 0, readableFont: false, lineSpacing: false, letterSpacing: false,
      highlightLinks: false, highContrast: false, colorTheme: "", grayscale: false,
      stopAnimations: false, enhancedFocus: false, bigCursor: false };
    var prefs;
    try { prefs = Object.assign({}, defaults, JSON.parse(localStorage.getItem(KEY) || "{}")); }
    catch (e) { prefs = Object.assign({}, defaults); }
    function save() { try { localStorage.setItem(KEY, JSON.stringify(prefs)); } catch (e) { /* ignore */ } }
    function setSwitch(node, on) { if (node) node.setAttribute("aria-checked", on ? "true" : "false"); }

    var map = {
      "a11y-readable-font": "readableFont", "a11y-line-spacing": "lineSpacing",
      "a11y-letter-spacing": "letterSpacing", "a11y-highlight-links": "highlightLinks",
      "a11y-high-contrast": "highContrast", "a11y-grayscale": "grayscale",
      "a11y-stop-animations": "stopAnimations", "a11y-enhanced-focus": "enhancedFocus",
      "a11y-big-cursor": "bigCursor"
    };

    function applyFontStep() {
      var pct = 100 + prefs.fontStep * 10;
      var scope = $("a11y-scope");
      if ("zoom" in scope.style) {
        scope.style.zoom = pct + "%";
        scope.style.transform = "";
      } else {
        var scale = pct / 100;
        scope.style.transformOrigin = "top left";
        scope.style.transform = scale === 1 ? "" : "scale(" + scale + ")";
        scope.style.width = scale === 1 ? "" : (100 / scale) + "%";
      }
      $("a11yFontSizeVal").textContent = pct + "%";
    }
    function applyAll() {
      applyFontStep();
      Object.keys(map).forEach(function (id) {
        var cls = id;  // class names mirror the switch ids
        root.classList.toggle(cls, !!prefs[map[id]]);
        setSwitch($(id), prefs[map[id]]);
      });
      root.classList.remove("a11y-theme-yellowblack", "a11y-theme-sepia");
      if (prefs.colorTheme) root.classList.add("a11y-theme-" + prefs.colorTheme);
      $("a11y-color-theme").value = prefs.colorTheme;
    }

    function onKey(e) { if (e.key === "Escape") closePanel(); }
    function onOutside(e) { if (!panel.contains(e.target) && !toggleBtn.contains(e.target)) closePanel(); }
    function openPanel() {
      panel.classList.add("open");
      toggleBtn.setAttribute("aria-expanded", "true");
      closeBtn.focus();
      document.addEventListener("keydown", onKey);
      document.addEventListener("click", onOutside, true);
    }
    function closePanel() {
      panel.classList.remove("open");
      toggleBtn.setAttribute("aria-expanded", "false");
      toggleBtn.focus();
      document.removeEventListener("keydown", onKey);
      document.removeEventListener("click", onOutside, true);
    }
    toggleBtn.addEventListener("click", function () { panel.classList.contains("open") ? closePanel() : openPanel(); });
    closeBtn.addEventListener("click", closePanel);

    Object.keys(map).forEach(function (id) {
      $(id).addEventListener("click", function () { prefs[map[id]] = !prefs[map[id]]; applyAll(); save(); });
    });
    $("a11y-color-theme").addEventListener("change", function (e) { prefs.colorTheme = e.target.value; applyAll(); save(); });
    document.querySelector('[data-a11y-action="fontsize-inc"]').addEventListener("click", function () {
      prefs.fontStep = Math.min(prefs.fontStep + 1, 5); applyFontStep(); save();
    });
    document.querySelector('[data-a11y-action="fontsize-dec"]').addEventListener("click", function () {
      prefs.fontStep = Math.max(prefs.fontStep - 1, -3); applyFontStep(); save();
    });
    $("a11yReset").addEventListener("click", function () { prefs = Object.assign({}, defaults); applyAll(); save(); stopSpeaking(); });

    // Read aloud: sentence-sized chunks avoid Chrome's ~15s utterance cut-off.
    var ttsSwitch = $("a11y-tts"), ttsBar = $("a11y-tts-bar"), pauseBtn = $("a11yTtsPause"), stopBtn = $("a11yTtsStop");
    var pauseSvg = pauseBtn.innerHTML;
    var playSvg = '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M7 5v14l11-7z"/></svg>';
    var queue = [], keepAlive = null;
    function chunks(text) {
      var parts = text.replace(/\s+/g, " ").trim().match(/[^.!?]+[.!?]*(\s|$)/g) || [text];
      var out = [], cur = "";
      parts.forEach(function (s) {
        if ((cur + s).length > 200) { if (cur) out.push(cur.trim()); cur = s; } else { cur += s; }
      });
      if (cur.trim()) out.push(cur.trim());
      return out;
    }
    function next() {
      if (!queue.length) { stopSpeaking(); return; }
      var u = new SpeechSynthesisUtterance(queue.shift());
      u.onend = next; u.onerror = next;
      window.speechSynthesis.speak(u);
    }
    function speak() {
      if (!("speechSynthesis" in window)) { showToast("Read-aloud isn't supported in this browser."); setSwitch(ttsSwitch, false); return; }
      var main = $("main-content");
      var text = main ? main.innerText : body.innerText;
      if (!text || !text.trim()) { setSwitch(ttsSwitch, false); return; }
      queue = chunks(text);
      window.speechSynthesis.cancel();
      setTimeout(next, 50);
      clearInterval(keepAlive);
      keepAlive = setInterval(function () {
        if (window.speechSynthesis.speaking && !window.speechSynthesis.paused) {
          window.speechSynthesis.pause(); window.speechSynthesis.resume();
        }
      }, 10000);
      ttsBar.classList.add("open");
      setSwitch(ttsSwitch, true);
    }
    function stopSpeaking() {
      clearInterval(keepAlive);
      queue = [];
      if ("speechSynthesis" in window) window.speechSynthesis.cancel();
      ttsBar.classList.remove("open");
      setSwitch(ttsSwitch, false);
      pauseBtn.innerHTML = pauseSvg;
    }
    ttsSwitch.addEventListener("click", function () {
      ttsSwitch.getAttribute("aria-checked") === "true" ? stopSpeaking() : speak();
    });
    pauseBtn.addEventListener("click", function () {
      if (!("speechSynthesis" in window)) return;
      if (window.speechSynthesis.paused) { window.speechSynthesis.resume(); pauseBtn.innerHTML = pauseSvg; }
      else { window.speechSynthesis.pause(); pauseBtn.innerHTML = playSvg; }
    });
    stopBtn.addEventListener("click", stopSpeaking);
    applyAll();
  }

  /* ---------------- Init ---------------- */
  function init() {
    applyTheme(resolveTheme());
    updateDate();
    buildWindLeaves();
    avatarFallback();
    initA11y();
    scheduleMidnight();
    if (body.dataset.preview === "1") {
      window.addEventListener("message", onPreviewMessage);
      try { window.parent.postMessage({ type: "lp-bio-preview-ready" }, location.origin); } catch (e) { /* ignore */ }
    }
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
