/* ============================================================
   LinkPlatform — bio-edit.js
   Progressive enhancement for the bio editor (/bio/edit).
   Every feature here has a no-JS fallback in the markup
   (plain forms, <select>s, up/down buttons).
   ============================================================ */
(function () {
  "use strict";
  document.documentElement.classList.add("js");

  function $(sel, root) { return (root || document).querySelector(sel); }
  function $$(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }
  function toast(msg, type) { if (window.lpToast) window.lpToast(msg, type || "success"); }
  function csrf() { var m = $('meta[name="csrf"]'); return m ? m.getAttribute("content") : ""; }

  var form = $("#profileForm");
  var frame = $("#previewFrame");
  var ICONS = {};
  try { JSON.parse($("#bioIconData").textContent).forEach(function (o) { ICONS[o.key] = o; }); } catch (e) { /* ignore */ }

  /* ---------------- Tabs ---------------- */
  var tabs = $$(".be-tab[data-tab]");
  function showTab(name, push) {
    tabs.forEach(function (t) {
      var on = t.dataset.tab === name;
      t.classList.toggle("on", on);
      t.setAttribute("aria-selected", on ? "true" : "false");
    });
    $$(".be-panel").forEach(function (p) {
      if (p.dataset.panel === name) p.removeAttribute("data-inactive");
      else p.setAttribute("data-inactive", "");
    });
    if (form) form.classList.toggle("links-active", name === "links");
    var rt = $("#returnTab");
    if (rt && name !== "links") rt.value = name;
    if (push) {
      var url = new URL(location.href);
      url.searchParams.set("tab", name);
      url.searchParams.delete("toast"); url.searchParams.delete("toast_type");
      history.replaceState(null, "", url.pathname + url.search + url.hash);
    }
  }
  tabs.forEach(function (t) {
    t.addEventListener("click", function (e) { e.preventDefault(); showTab(t.dataset.tab, true); });
  });
  var initial = (tabs.filter(function (t) { return t.classList.contains("on"); })[0] || tabs[0]);
  if (initial) showTab(initial.dataset.tab, false);

  /* ---------------- Character counters ---------------- */
  $$("[data-counter]").forEach(function (el) {
    if (!(el.maxLength > 0)) return;
    var c = document.createElement("span");
    c.className = "be-counter";
    el.insertAdjacentElement("afterend", c);
    function upd() {
      var max = el.maxLength;  // read live: link type changes the limit
      c.textContent = el.value.length + " / " + max;
      c.classList.toggle("near", el.value.length > max * 0.9);
    }
    el.addEventListener("input", upd);
    upd();
  });

  /* ---------------- Insert-text helper (•) ---------------- */
  $$("[data-insert]").forEach(function (b) {
    b.addEventListener("click", function () {
      var ta = document.getElementById(b.dataset.insert);
      if (!ta) return;
      var s = ta.selectionStart || ta.value.length, e = ta.selectionEnd || ta.value.length;
      ta.value = ta.value.slice(0, s) + b.dataset.text + ta.value.slice(e);
      ta.focus();
      ta.selectionStart = ta.selectionEnd = s + b.dataset.text.length;
      ta.dispatchEvent(new Event("input", { bubbles: true }));
    });
  });

  /* ---------------- Live preview bridge ---------------- */
  var avatarData = null;
  function val(name) { var el = form && form.elements[name]; return el ? el.value : ""; }
  function checked(name) { var el = form && form.elements[name]; return !!(el && el.checked); }
  function radio(name) {
    var el = form && form.querySelector('input[name="' + name + '"]:checked');
    return el ? el.value : "";
  }
  function previewState() {
    var name = val("display_name");
    var footer = val("pref_footer_text").trim() || ("© " + new Date().getFullYear() + " " + name);
    return {
      type: "lp-bio-preview",
      name: name, bio: val("bio"), footer: footer,
      theme: radio("theme") || "default",
      customPrimary: checked("pref_custom_accent") ? val("accent_color") : "",
      scene: checked("pref_scene"), tech: checked("pref_tech"),
      effects: val("pref_effects") || "auto",
      seasonalTagline: checked("pref_seasonal_tagline"),
      layout: radio("pref_layout") || "grid",
      share: checked("pref_show_share"),
      report: checked("pref_show_report"), date: checked("pref_show_date"),
      avatar: avatarData
    };
  }
  var sendTimer = null;
  function sendPreview() {
    clearTimeout(sendTimer);
    sendTimer = setTimeout(function () {
      if (!frame || !frame.contentWindow || !form) return;
      try { frame.contentWindow.postMessage(previewState(), location.origin); } catch (e) { /* ignore */ }
    }, 60);
  }
  function reloadPreview() {
    if (!frame) return;
    var st = $("[data-preview-state]");
    if (st) st.textContent = "Refreshing…";
    frame.src = frame.src.split("#")[0];
  }
  window.addEventListener("message", function (e) {
    if (e.origin !== location.origin || !e.data) return;
    if (e.data.type === "lp-bio-preview-ready") {
      var st = $("[data-preview-state]");
      if (st) st.textContent = "Updates as you type";
      if (dirty) sendPreview();  // re-apply unsaved edits after a reload
    }
  });
  var rl = $("[data-preview-reload]");
  if (rl) rl.addEventListener("click", reloadPreview);

  /* ---------------- Dirty tracking + save bar ---------------- */
  var dirty = false;
  var bar = $("[data-savebar]"), msg = $("[data-savebar-msg]"), discard = $("[data-discard]");
  var cleanMsg = msg ? msg.textContent : "";
  function setDirty(on) {
    dirty = on;
    if (bar) bar.classList.toggle("dirty", on);
    if (msg) msg.textContent = on ? "You have unsaved changes" : cleanMsg;
    if (discard) discard.hidden = !on;
  }
  if (form) {
    form.addEventListener("input", function () { setDirty(true); sendPreview(); });
    form.addEventListener("change", function () { setDirty(true); sendPreview(); });
    form.addEventListener("submit", function () { dirty = false; });
    form.addEventListener("reset", function () {
      setTimeout(function () {
        avatarData = null;
        resetAvatarPreview();
        $$("[data-counter]", form).forEach(function (el) { el.dispatchEvent(new Event("input")); });
        setDirty(false);
        reloadPreview();
      }, 0);
    });
    window.addEventListener("beforeunload", function (e) {
      if (dirty) { e.preventDefault(); e.returnValue = ""; }
    });
  }

  /* ---------------- Avatar preview ---------------- */
  var avatarBox = $("#avatarPreview");
  var avatarOrig = avatarBox ? avatarBox.innerHTML : "";
  function resetAvatarPreview() { if (avatarBox) avatarBox.innerHTML = avatarOrig; }
  var file = $("#avatar");
  if (file) {
    file.addEventListener("change", function () {
      var f = file.files && file.files[0];
      if (!f) return;
      if (f.size > 2 * 1024 * 1024) { toast("That image is over 2 MB.", "error"); file.value = ""; return; }
      var r = new FileReader();
      r.onload = function () {
        avatarData = r.result;
        if (avatarBox) {
          avatarBox.innerHTML = "";
          var img = document.createElement("img");
          img.src = avatarData; img.alt = "New photo";
          avatarBox.appendChild(img);
        }
        sendPreview();
      };
      r.readAsDataURL(f);
    });
  }

  /* ---------------- Link forms: type-aware fields ---------------- */
  function applyKind(lf) {
    var k = (lf.querySelector('input[name="kind"]:checked') || {}).value || "link";
    $$("[data-show-kinds]", lf).forEach(function (el) {
      el.hidden = el.dataset.showKinds.split(" ").indexOf(k) < 0;
    });
    $$("[data-label-for-kind]", lf).forEach(function (lab) {
      if (!lab.dataset.defaultLabel) lab.dataset.defaultLabel = lab.textContent;
      var map = {};
      try { map = JSON.parse(lab.dataset.labelForKind); } catch (e) { map = {}; }
      lab.textContent = map[k] || lab.dataset.defaultLabel;
    });
    var url = lf.querySelector('input[name="url"]');
    if (url) url.required = k === "link";
    var desc = lf.querySelector('textarea[name="description"]');
    if (desc) {
      desc.required = k === "copy";
      desc.placeholder = k === "copy" ? "e.g. PO BOX 1357, LINDSAY, CA 93247"
        : (k.indexOf("notice") === 0 ? "e.g. I'm not on X, Facebook or TikTok — any profile there isn't me." : "A short line under the title");
      desc.maxLength = k.indexOf("notice") === 0 ? 600 : 160;
      desc.dispatchEvent(new Event("input"));
    }
  }

  function updateTile(lf) {
    var tile = lf.querySelector("[data-icon-preview]");
    var sel = lf.querySelector('select[name="icon"]');
    if (!tile || !sel) return;
    var key = sel.value;
    if (!key) {
      // Auto: guess from the URL host like the server does (common cases only)
      var u = ((lf.querySelector('input[name="url"]') || {}).value || "").toLowerCase();
      var guesses = ["youtube", "github", "mastodon", "twitch", "discord", "telegram", "whatsapp", "signal",
        "reddit", "pinterest", "linkedin", "instagram", "facebook", "tiktok"];
      if (u.indexOf("mailto:") === 0) key = "email";
      else if (/youtu\.be/.test(u)) key = "youtube";
      else if (/bsky/.test(u)) key = "bluesky";
      else guesses.forEach(function (g) { if (!key && u.indexOf(g) >= 0) key = g; });
      key = key || "link";
    }
    var o = ICONS[key] || ICONS.link || {};
    if (o.svg) tile.innerHTML = o.svg;
    var useColor = lf.querySelector('input[name="use_color"]');
    var color = lf.querySelector('input[name="color"]');
    var c = (useColor && useColor.checked && color) ? color.value : (o.color || "");
    if (c) tile.style.setProperty("--ic", c); else tile.style.removeProperty("--ic");
    if (color) color.disabled = !(useColor && useColor.checked);
  }

  $$("[data-link-form]").forEach(function (lf) {
    applyKind(lf);
    updateTile(lf);
    lf.addEventListener("change", function (e) {
      if (e.target.name === "kind") applyKind(lf);
      updateTile(lf);
    });
    lf.addEventListener("input", function (e) {
      if (e.target.name === "url" || e.target.name === "color") updateTile(lf);
      if (e.target.name === "section") markChips(lf);
    });
    // Section chips
    $$("[data-section-chips]", lf).forEach(function (box) {
      box.addEventListener("click", function (e) {
        var chip = e.target.closest(".be-chip");
        if (!chip) return;
        var input = document.getElementById(box.dataset.sectionChips);
        if (input) { input.value = chip.dataset.value; input.dispatchEvent(new Event("input", { bubbles: true })); }
      });
    });
    markChips(lf);
    // Icon picker button
    var pick = lf.querySelector(".be-pick-icon");
    if (pick && typeof HTMLDialogElement === "function") {
      pick.hidden = false;
      pick.addEventListener("click", function () { openPicker(lf.querySelector('select[name="icon"]')); });
    }
    lf.addEventListener("submit", function (e) {
      if (!lf.checkValidity()) {
        e.preventDefault();
        lf.reportValidity();
      }
    });
  });

  function markChips(lf) {
    var input = lf.querySelector('input[name="section"]');
    $$(".be-chip", lf).forEach(function (c) { c.classList.toggle("on", !!input && c.dataset.value === input.value); });
  }

  /* ---------------- Icon picker dialog ---------------- */
  var dlg = $("#iconPicker"), pickTarget = null;
  function openPicker(select) {
    if (!dlg || !select) return;
    pickTarget = select;
    $$(".be-icon-opt", dlg).forEach(function (b) { b.classList.toggle("on", b.dataset.icon === select.value); b.hidden = false; });
    var s = $("[data-icon-search]", dlg);
    if (s) s.value = "";
    dlg.showModal();
    var on = $(".be-icon-opt.on", dlg);
    if (on) on.focus();
  }
  if (dlg) {
    dlg.addEventListener("click", function (e) {
      var opt = e.target.closest(".be-icon-opt");
      if (opt && pickTarget) {
        pickTarget.value = opt.dataset.icon;
        pickTarget.dispatchEvent(new Event("change", { bubbles: true }));
        dlg.close();
        return;
      }
      if (e.target.closest("[data-close-dialog]") || e.target === dlg) dlg.close();
    });
    var search = $("[data-icon-search]", dlg);
    if (search) search.addEventListener("input", function () {
      var q = search.value.trim().toLowerCase();
      $$(".be-icon-opt", dlg).forEach(function (b) { b.hidden = !!q && b.dataset.label.indexOf(q) < 0 && b.dataset.icon.indexOf(q) < 0; });
    });
  }

  /* ---------------- Quick show/hide ---------------- */
  $$("[data-toggle-form]").forEach(function (tf) {
    tf.addEventListener("submit", function (e) {
      e.preventDefault();
      var li = tf.closest(".be-item");
      fetch(tf.action, { method: "POST", credentials: "same-origin",
        headers: { "x-csrf-token": csrf(), "Accept": "application/json" } })
        .then(function (r) { if (!r.ok) throw new Error(); return r.json(); })
        .then(function (d) {
          var btn = tf.querySelector("button");
          var title = (li.querySelector(".be-item-text strong") || {}).textContent || "";
          li.classList.toggle("is-hidden", !d.is_active);
          btn.setAttribute("aria-pressed", d.is_active ? "false" : "true");
          btn.title = d.is_active ? "Hide" : "Show";
          btn.setAttribute("aria-label", (d.is_active ? "Hide " : "Show ") + title);
          var row = li.querySelector(".be-item-row"), tag = row.querySelector(".tag-dim");
          if (!d.is_active && !tag) {
            tag = document.createElement("span"); tag.className = "tag tag-dim"; tag.textContent = "Hidden";
            row.insertBefore(tag, row.querySelector(".be-edit-btn"));
          } else if (d.is_active && tag) tag.remove();
          var cb = li.querySelector('input[name="is_active"]');
          if (cb) cb.checked = d.is_active;
          toast(d.is_active ? "Now visible on your page" : "Hidden from your page");
          reloadPreview();
        })
        .catch(function () { tf.submit(); });
    });
  });

  /* ---------------- Drag & drop / keyboard reorder ---------------- */
  var lists = $$("[data-dropzone]");
  var dragging = null, saveTimer = null;

  function sectionOf(li) { var s = li.closest(".be-section"); return s ? s.dataset.section : ""; }

  function refreshCounts() {
    $$(".be-section").forEach(function (s) {
      var n = s.querySelectorAll(".be-item").length;
      var c = s.querySelector(".be-section-head .be-count");
      if (c) c.textContent = n;
    });
  }

  function saveOrder() {
    clearTimeout(saveTimer);
    saveTimer = setTimeout(function () {
      var ids = [], sections = {};
      $$(".be-item").forEach(function (li) {
        ids.push(parseInt(li.dataset.id, 10));
        var sec = sectionOf(li);
        if (li.dataset.origSection !== sec) sections[li.dataset.id] = sec;
      });
      fetch("/bio/links/reorder", {
        method: "POST", credentials: "same-origin",
        headers: { "x-csrf-token": csrf(), "Content-Type": "application/json", "Accept": "application/json" },
        body: JSON.stringify({ ids: ids, sections: sections })
      }).then(function (r) {
        if (!r.ok) throw new Error(r.status);
        $$(".be-item").forEach(function (li) {
          li.dataset.origSection = sectionOf(li);
          var input = li.querySelector('input[name="section"]');
          if (input) input.value = li.dataset.origSection;
        });
        refreshCounts();
        toast("Order saved");
        reloadPreview();
      }).catch(function () {
        toast("Couldn't save the new order — reloading.", "error");
        setTimeout(function () { location.reload(); }, 1200);
      });
    }, 250);
  }

  $$(".be-item").forEach(function (li) { li.dataset.origSection = sectionOf(li); });

  function itemAt(x, y) {
    var el = document.elementFromPoint(x, y);
    if (!el) return {};
    return { item: el.closest(".be-item"), list: el.closest("[data-dropzone]") };
  }

  $$("[data-grip]").forEach(function (grip) {
    var li = grip.closest(".be-item");
    // A button inside <summary> would toggle the details; stop that.
    grip.addEventListener("click", function (e) { e.preventDefault(); e.stopPropagation(); });

    grip.addEventListener("pointerdown", function (e) {
      if (e.button !== 0) return;
      e.preventDefault();
      dragging = li;
      li.classList.add("dragging");
      // Listen on the document, not the grip: moving the row in the DOM
      // releases pointer capture, which would strand the drag.
      var startOrder = $$(".be-item").map(function (x) { return x.dataset.id + ":" + sectionOf(x); }).join(",");

      function move(ev) {
        var hit = itemAt(ev.clientX, ev.clientY);
        lists.forEach(function (l) { l.classList.toggle("drop-target", l === hit.list && hit.list !== li.parentNode); });
        if (hit.item && hit.item !== li) {
          var r = hit.item.getBoundingClientRect();
          var after = ev.clientY > r.top + r.height / 2;
          hit.item.parentNode.insertBefore(li, after ? hit.item.nextSibling : hit.item);
        } else if (hit.list && !hit.item && hit.list !== li.parentNode) {
          hit.list.appendChild(li);
        }
        // auto-scroll near viewport edges
        if (ev.clientY < 80) window.scrollBy(0, -12);
        else if (ev.clientY > window.innerHeight - 80) window.scrollBy(0, 12);
      }
      function up() {
        document.removeEventListener("pointermove", move);
        document.removeEventListener("pointerup", up);
        document.removeEventListener("pointercancel", up);
        li.classList.remove("dragging");
        lists.forEach(function (l) { l.classList.remove("drop-target"); });
        dragging = null;
        var endOrder = $$(".be-item").map(function (x) { return x.dataset.id + ":" + sectionOf(x); }).join(",");
        if (endOrder !== startOrder) { refreshCounts(); saveOrder(); }
      }
      document.addEventListener("pointermove", move);
      document.addEventListener("pointerup", up);
      document.addEventListener("pointercancel", up);
    });

    grip.addEventListener("keydown", function (e) {
      if (e.key !== "ArrowUp" && e.key !== "ArrowDown") return;
      e.preventDefault();
      var all = $$(".be-item");
      var i = all.indexOf(li);
      if (e.key === "ArrowUp") {
        var prev = li.previousElementSibling;
        if (prev) li.parentNode.insertBefore(li, prev);
        else {
          var pl = lists[lists.indexOf(li.parentNode) - 1];
          if (!pl) return;
          pl.appendChild(li);
        }
      } else {
        var next = li.nextElementSibling;
        if (next) li.parentNode.insertBefore(next, li);
        else {
          var nl = lists[lists.indexOf(li.parentNode) + 1];
          if (!nl) return;
          nl.insertBefore(li, nl.firstChild);
        }
      }
      if (i !== $$(".be-item").indexOf(li) || li.dataset.origSection !== sectionOf(li)) {
        grip.focus();
        refreshCounts();
        saveOrder();
      }
    });
  });

  /* ---------------- Deep link to an item (#link-12) ---------------- */
  function focusHash() {
    var m = /^#link-(\d+)$/.exec(location.hash);
    if (!m) return;
    var li = document.getElementById("link-" + m[1]);
    if (!li) return;
    showTab("links", false);
    li.classList.add("flash");
    setTimeout(function () { li.scrollIntoView({ block: "center", behavior: "smooth" }); }, 50);
  }
  focusHash();
  window.addEventListener("hashchange", focusHash);

  // Collapse the add form after a successful add so the new item is visible.
  var add = $("#addItem");
  if (add && /^#link-/.test(location.hash) && $$(".be-item").length) add.open = false;
})();
