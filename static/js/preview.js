/* Preview page: renders the parse preview, then runs the analysis while
   polling the backend for the real pipeline stage. */
(function () {
  "use strict";

  var id = document.body.dataset.analysisId;
  var $ = function (sel) { return document.querySelector(sel); };

  var STAGE_TEXT = {
    "Preparing": "Preparing the file\u2026",
    "Cleaning data": "Cleaning data - removing duplicates, normalising timestamps\u2026",
    "Running model": "Running the model over your records\u2026",
    "Assigning severity": "Scoring severity per detection\u2026",
    "Summarising": "Summarising results\u2026"
  };

  function td(text, cls) {
    var cell = document.createElement("td");
    cell.textContent = text;
    if (cls) { cell.className = cls; }
    return cell;
  }

  function fillTable(table, headers, rows, titleColumn) {
    var thead = table.querySelector("thead");
    var tbody = table.querySelector("tbody");
    thead.textContent = "";
    tbody.textContent = "";
    var headRow = document.createElement("tr");
    headers.forEach(function (h) {
      var th = document.createElement("th");
      th.scope = "col";
      th.textContent = h;
      headRow.appendChild(th);
    });
    thead.appendChild(headRow);
    rows.forEach(function (row) {
      var tr = document.createElement("tr");
      row.forEach(function (value, i) {
        var cell = td(String(value));
        if (i === titleColumn && String(value).length > 0) {
          cell.title = String(value);
          cell.classList.add("event-cell");
        }
        tr.appendChild(cell);
      });
      tbody.appendChild(tr);
    });
  }

  function showError(message) {
    $("#preview-section").hidden = true;
    $("#preview-failed").hidden = false;
    $("#preview-error").textContent = message;
  }

  function render(p) {
    var summary = $("#preview-summary");
    var items = [
      ["File", p.filename],
      ["Type", p.detected_type || "unknown"],
      ["Rows", Number(p.row_count).toLocaleString()],
      ["Columns", p.column_count]
    ];
    if (p.parse_success_rate !== null && p.parse_success_rate !== undefined) {
      items.push(["Lines parsed", Math.round(p.parse_success_rate * 100) + "%"]);
    }
    if (p.duplicates_detected > 0) {
      items.push(["Duplicate rows", p.duplicates_detected]);
    }
    items.forEach(function (pair) {
      var div = document.createElement("div");
      div.className = "summary-item";
      var k = document.createElement("span");
      k.className = "k";
      k.textContent = pair[0];
      var v = document.createElement("span");
      v.className = "v";
      v.textContent = pair[1];
      div.appendChild(k);
      div.appendChild(v);
      summary.appendChild(div);
    });

    var sampleRows = p.rows.map(function (row) {
      return Object.keys(row).map(function (key) { return row[key]; });
    });
    if (sampleRows.length) {
      var headers = Object.keys(p.rows[0]);
      fillTable($("#preview-table"), headers, sampleRows, headers.indexOf("event"));
    }

    fillTable($("#columns-table"), ["Column", "Role", "Missing"],
      p.columns.map(function (c) { return [c.name, c.role, c.missing]; }), -1);

    if (p.numeric_stats.length) {
      $("#numeric-section").hidden = false;
      fillTable($("#numeric-table"), ["Column", "Count", "Mean", "Min", "Max"],
        p.numeric_stats.map(function (s) {
          return [s.name, s.count, s.mean, s.min, s.max];
        }), -1);
    }

    var warnings = $("#preview-warnings");
    warnings.textContent = "";
    (p.warnings || []).forEach(function (text) {
      var li = document.createElement("li");
      li.textContent = text;
      warnings.appendChild(li);
    });

    $("#preview-section").hidden = false;

    var analyzeBtn = $("#analyze-btn");
    var analyzeStatus = $("#analyze-status");
    var progress = $("#analyze-progress");

    // The preview loaded, which means the upload succeeded - analysis may start.
    analyzeBtn.disabled = false;

    function fail(message) {
      progress.hidden = true;
      analyzeBtn.disabled = false;
      analyzeStatus.textContent = "";
      $("#preview-failed").hidden = false;
      $("#preview-error").textContent = message + " Nothing was changed - try another file or reload.";
    }

    function poll() {
      fetch("/api/progress/" + id)
        .then(function (r) { return r.json(); })
        .then(function (state) {
          if (state.status === "done") {
            window.location.href = "/dashboard/" + id;
          } else if (state.status === "failed") {
            fail(state.error || "The analysis failed.");
          } else if (state.status === "running") {
            analyzeStatus.textContent = STAGE_TEXT[state.stage] || (state.stage + "\u2026");
            window.setTimeout(poll, 700);
          } else {
            window.setTimeout(poll, 900);
          }
        })
        .catch(function () { fail("Lost contact with the server while analysing."); });
    }

    analyzeBtn.addEventListener("click", function () {
      analyzeBtn.disabled = true;
      progress.hidden = false;
      analyzeStatus.textContent = "Starting\u2026";
      fetch("/api/analyze/" + id, { method: "POST" })
        .then(function (r) { return r.json(); })
        .then(function (reply) {
          if (reply.error) {
            fail(reply.error);
          } else {
            poll();
          }
        })
        .catch(function () { fail("The analysis could not be started."); });
    });
  }

  fetch("/api/preview/" + id)
    .then(function (r) { return r.json(); })
    .then(function (preview) {
      if (preview.error) { showError(preview.error); } else { render(preview); }
    })
    .catch(function () { showError("The preview could not be loaded."); });
})();
