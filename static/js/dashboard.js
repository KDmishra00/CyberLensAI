/* Dashboard rendering. One fetch for the results, one for each page of
   detections. All user-derived strings go through textContent. */
(function () {
  "use strict";

  var id = document.body.dataset.analysisId;
  var $ = function (sel) { return document.querySelector(sel); };
  var Charts = window.CyberLensCharts;

  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) { node.className = cls; }
    if (text !== undefined) { node.textContent = text; }
    return node;
  }

  function severityLabel(sev, count) {
    var item = el("span", "sev-item");
    item.appendChild(el("span", "sev-count", String(count)));
    var label = el("span", "sev sev-" + sev.toLowerCase(), sev);
    item.appendChild(label);
    return item;
  }

  function renderStats(r) {
    $("#stat-total").textContent = r.total_records.toLocaleString();
    $("#stat-attacks").textContent = r.total_attacks.toLocaleString();
    $("#stat-normal").textContent = r.total_normal.toLocaleString();
    $("#stat-rate").textContent = r.attack_pct.toFixed(1) + "%";
  }

  function renderCategoryTable(r) {
    var tbody = $("#category-table tbody");
    tbody.textContent = "";
    Object.keys(r.category_counts).forEach(function (cat) {
      var tr = el("tr");
      var nameCell = el("td");
      var dot = el("span", "", "\u25A0 ");
      dot.style.color = Charts.colorFor(cat, Object.keys(r.category_counts).indexOf(cat));
      nameCell.appendChild(dot);
      nameCell.appendChild(document.createTextNode(cat));
      tr.appendChild(nameCell);
      tr.appendChild(el("td", "", r.category_counts[cat].toLocaleString()));
      tr.appendChild(el("td", "", r.category_pct[cat].toFixed(1) + "%"));
      tbody.appendChild(tr);
    });
  }

  function renderCharts(r) {
    Charts.renderCategoryCharts(r.category_counts);
    Charts.renderTimeline(r.timeline, r.timeline_note);
    $("#timeline-note").textContent = r.timeline.length ? (r.timeline_note || "") : "";
  }

  function renderSeverity(r) {
    var wrap = $("#severity-inline");
    wrap.textContent = "";
    Object.keys(r.severity_counts).forEach(function (sev) {
      wrap.appendChild(severityLabel(sev, r.severity_counts[sev]));
    });
  }

  function renderTopTables(r) {
    var tbody = $("#topips-table tbody");
    tbody.textContent = "";
    if (!r.top_ips.length) {
      var empty = el("tr");
      empty.appendChild(el("td", "muted", "No attacks, so no attacker addresses."));
      empty.firstElementChild.colSpan = 4;
      tbody.appendChild(empty);
    }
    r.top_ips.forEach(function (ip) {
      var tr = el("tr");
      tr.appendChild(el("td", "mono", ip.src_ip));
      tr.appendChild(el("td", "", String(ip.attacks)));
      tr.appendChild(el("td", "", ip.dominant));
      tr.appendChild(el("td", "", ip.max_severity || "-"));
      tbody.appendChild(tr);
    });

    var targets = $("#top-targets");
    targets.textContent = "";
    var users = r.top_targets.usernames || [];
    var ports = r.top_targets.ports || [];
    if (!users.length && !ports.length) {
      targets.appendChild(el("p", "muted",
        "Nothing was targeted enough to list. The file may not record usernames or ports."));
      return;
    }
    if (users.length) {
      targets.appendChild(el("h3", "", "Usernames"));
      var ul = el("ul", "", "");
      ul.style.margin = "0";
      users.forEach(function (u) {
        ul.appendChild(el("li", "", u.name + " - " + u.count + " events"));
      });
      targets.appendChild(ul);
    }
    if (ports.length) {
      targets.appendChild(el("h3", "", "Ports"));
      var pl = el("ul", "", "");
      pl.style.margin = "0";
      ports.forEach(function (p) {
        pl.appendChild(el("li", "", "Port " + p.port + " - " + p.count + " events"));
      });
      targets.appendChild(pl);
    }
  }

  function renderMitigations(r) {
    var wrap = $("#mitigations");
    wrap.textContent = "";
    if (!r.mitigations.length) {
      wrap.appendChild(el("p", "muted",
        "Nothing was detected, so there is nothing to mitigate. Routine hardening never hurts, though."));
      return;
    }
    r.mitigations.forEach(function (m) {
      var block = el("div", "mitigation");
      var head = el("h3", "", m.category);
      if (m.mitre && m.mitre.length) {
        head.appendChild(el("span", "muted small", "  MITRE ATT&CK " + m.mitre.join(", ")));
      }
      block.appendChild(head);
      block.appendChild(el("p", "", m.summary));
      var ol = el("ol");
      m.steps.forEach(function (step) { ol.appendChild(el("li", "", step)); });
      block.appendChild(ol);
      wrap.appendChild(block);
    });
  }

  function renderCaveats(r) {
    if (r.model_accuracy !== null && r.model_accuracy !== undefined) {
      $("#caveat-accuracy").textContent =
        "On its own held-out synthetic test set, the model scores " +
        Math.round(r.model_accuracy * 1000) / 10 + "% accuracy (trained " +
        (r.model_trained_at || "unknown date") + "). Real logs will be harder.";
    }
    if (r.low_confidence_count > 0) {
      $("#caveat-lowconf").hidden = false;
      $("#caveat-lowconf").textContent =
        r.low_confidence_count.toLocaleString() +
        " events were called attacks with confidence below 0.55. They are counted as normal " +
        "in the numbers above rather than inflating the attack count.";
    }
    if (r.reliability_warning) {
      var warn = $("#caveat-warning");
      warn.hidden = false;
      warn.textContent = r.reliability_warning;
    }
  }

  /* --- detections table (server-side filter/sort/pagination) ------------ */

  var detState = { page: 1, q: "", category: "", severity: "", sort: "severity", dir: "desc" };
  var mitigationMap = {};

  function renderFilters(r) {
    var catSel = $("#filter-category");
    catSel.appendChild(el("option", "", "All categories")).value = "";
    Object.keys(r.category_counts).forEach(function (cat) {
      var opt = el("option", "", cat);
      opt.value = cat;
      catSel.appendChild(opt);
    });
    var sevSel = $("#filter-severity");
    sevSel.appendChild(el("option", "", "All severities")).value = "";
    ["Low", "Medium", "High", "Critical"].forEach(function (sev) {
      var opt = el("option", "", sev);
      opt.value = sev;
      sevSel.appendChild(opt);
    });
    $("#filter-form").addEventListener("submit", function (event) {
      event.preventDefault();
      detState.q = $("#filter-q").value;
      detState.category = catSel.value;
      detState.severity = sevSel.value;
      detState.page = 1;
      loadDetections();
    });
    $("#filter-reset").addEventListener("click", function () {
      detState = { page: 1, q: "", category: "", severity: "", sort: detState.sort, dir: detState.dir };
      $("#filter-q").value = "";
      catSel.value = "";
      sevSel.value = "";
      loadDetections();
    });
    document.querySelectorAll(".th-sort").forEach(function (button) {
      button.addEventListener("click", function () {
        var key = button.dataset.sort;
        if (detState.sort === key) {
          detState.dir = detState.dir === "asc" ? "desc" : "asc";
        } else {
          detState.sort = key;
          detState.dir = "asc";
        }
        loadDetections();
      });
    });
  }

  function markSortButtons() {
    document.querySelectorAll(".th-sort").forEach(function (button) {
      if (button.dataset.sort === detState.sort) {
        button.setAttribute("aria-sort", detState.dir === "asc" ? "ascending" : "descending");
      } else {
        button.removeAttribute("aria-sort");
      }
    });
  }

  function loadDetections() {
    var params = new URLSearchParams();
    params.set("page", detState.page);
    if (detState.q) { params.set("q", detState.q); }
    if (detState.category) { params.set("category", detState.category); }
    if (detState.severity) { params.set("severity", detState.severity); }
    params.set("sort", detState.sort);
    params.set("dir", detState.dir);

    fetch("/api/detections/" + id + "?" + params.toString())
      .then(function (r) { return r.json(); })
      .then(function (payload) {
        if (payload.error) { return; }
        markSortButtons();
        renderDetectionRows(payload.rows);
        renderPagination(payload);
        $("#detections-count").textContent = payload.total
          ? payload.total.toLocaleString() + " detections match. Click a row for the full event."
          : "No detections match these filters.";
      });
  }

  function renderDetectionRows(rows) {
    var tbody = $("#detections-table tbody");
    tbody.textContent = "";
    rows.forEach(function (row) {
      var tr = el("tr");
      tr.tabIndex = 0;
      tr.setAttribute("role", "button");
      tr.setAttribute("aria-expanded", "false");
      tr.appendChild(el("td", "", row.timestamp || "-"));
      tr.appendChild(el("td", "mono", row.src_ip || "-"));
      tr.appendChild(el("td", "", row.username || "-"));
      tr.appendChild(el("td", "", row.category));
      var sevCell = el("td");
      sevCell.appendChild(el("span", "sev sev-" + String(row.severity).toLowerCase(), row.severity));
      tr.appendChild(sevCell);
      tr.appendChild(el("td", "", row.confidence.toFixed(2)));
      var eventCell = el("td", "event-cell", row.event);
      eventCell.title = row.event;
      tr.appendChild(eventCell);

      function toggle() {
        var existing = tr.nextElementSibling;
        if (existing && existing.classList.contains("det-expand")) {
          existing.remove();
          tr.setAttribute("aria-expanded", "false");
          return;
        }
        document.querySelectorAll("#detections-table .det-expand").forEach(function (n) { n.remove(); });
        var expand = el("tr", "det-expand");
        var cell = el("td");
        cell.colSpan = 7;
        var strong = el("strong", "", "Row " + row.row_id + " - full event");
        cell.appendChild(strong);
        cell.appendChild(el("p", "", row.event));
        var mit = mitigationMap[row.category];
        if (mit) {
          cell.appendChild(el("strong", "", "Recommended response"));
          var ol = el("ol");
          mit.steps.forEach(function (step) { ol.appendChild(el("li", "", step)); });
          cell.appendChild(ol);
        }
        expand.appendChild(cell);
        tr.after(expand);
        tr.setAttribute("aria-expanded", "true");
      }
      tr.addEventListener("click", toggle);
      tr.addEventListener("keydown", function (event) {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          toggle();
        }
      });
      tbody.appendChild(tr);
    });
  }

  function renderPagination(payload) {
    var nav = $("#pagination");
    nav.textContent = "";
    if (payload.last_page <= 1) { return; }
    var pages = [];
    var current = payload.page;
    var last = payload.last_page;
    pages.push(1);
    for (var p = current - 2; p <= current + 2; p++) {
      if (p > 1 && p < last) { pages.push(p); }
    }
    pages.push(last);
    pages = pages.filter(function (value, i, arr) { return arr.indexOf(value) === i; })
                 .sort(function (a, b) { return a - b; });

    var prev = el("button", "", "\u2190");
    prev.type = "button";
    prev.disabled = current === 1;
    prev.addEventListener("click", function () { detState.page = current - 1; loadDetections(); });
    nav.appendChild(prev);

    pages.forEach(function (p, i) {
      if (i > 0 && p - pages[i - 1] > 1) {
        nav.appendChild(el("span", "ellipsis", "\u2026"));
      }
      (function (pageNo) {
        var button = el("button", "", String(pageNo));
        button.type = "button";
        if (pageNo === current) { button.setAttribute("aria-current", "page"); }
        button.addEventListener("click", function () { detState.page = pageNo; loadDetections(); });
        nav.appendChild(button);
      })(p);
    });

    var next = el("button", "", "\u2192");
    next.type = "button";
    next.disabled = current === last;
    next.addEventListener("click", function () { detState.page = current + 1; loadDetections(); });
    nav.appendChild(next);
  }

  /* --- explore panel ------------------------------------------------------ */

  function renderExplore(r) {
    var toggle = $("#explore-toggle");
    toggle.addEventListener("click", function () {
      var body = $("#explore-body");
      var open = toggle.getAttribute("aria-expanded") === "true";
      toggle.setAttribute("aria-expanded", String(!open));
      body.hidden = open;
      if (!open && !body.dataset.rendered && r.explore) {
        body.dataset.rendered = "1";
        Charts.renderScatter(r.explore);
      }
    });
    if (!r.explore) {
      toggle.disabled = true;
      toggle.textContent = "Explore the data in 2-D (not available for this file)";
    }
  }

  /* --- delete -------------------------------------------------------------- */

  function wireDelete() {
    $("#delete-btn").addEventListener("click", function () {
      var button = $("#delete-btn");
      button.disabled = true;
      fetch("/api/delete/" + id, { method: "POST" })
        .then(function () { window.location.href = "/upload"; })
        .catch(function () { button.disabled = false; });
    });
  }

  /* --- boot ------------------------------------------------------------------ */

  fetch("/api/results/" + id)
    .then(function (r) { return r.json(); })
    .then(function (r) {
      if (r.error) {
        var box = $("#dash-error");
        box.hidden = false;
        box.textContent = r.error;
        return;
      }
      Charts.init();
      r.mitigations.forEach(function (m) { mitigationMap[m.category] = m; });
      renderStats(r);
      renderCategoryTable(r);
      renderCharts(r);
      renderSeverity(r);
      renderTopTables(r);
      renderMitigations(r);
      renderCaveats(r);
      renderFilters(r);
      loadDetections();
      renderExplore(r);
      wireDelete();
    })
    .catch(function () {
      var box = $("#dash-error");
      box.hidden = false;
      box.textContent = "The results could not be loaded. The analysis may have expired.";
    });
})();
