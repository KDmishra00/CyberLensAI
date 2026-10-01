/* Chart.js wrappers. Colours are read from CSS custom properties so the
   charts follow the light/dark theme automatically. */
(function () {
  "use strict";

  var palette = [];
  var normalColor = "#9A9891";
  var categoryColors = {};

  function cssVar(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  }

  function init() {
    var Chart = window.Chart;
    palette = [cssVar("--chart-1"), cssVar("--chart-2"), cssVar("--chart-3"),
               cssVar("--chart-4"), cssVar("--chart-5"), cssVar("--chart-6")];
    normalColor = cssVar("--chart-normal");
    Chart.defaults.color = cssVar("--muted");
    Chart.defaults.borderColor = cssVar("--border");
    Chart.defaults.font.family = getComputedStyle(document.body).fontFamily;
  }

  function colorFor(category, index) {
    if (!categoryColors[category]) {
      categoryColors[category] = category === "Normal" ? normalColor
                                                       : palette[index % palette.length];
    }
    return categoryColors[category];
  }

  function renderCategoryCharts(categoryCounts) {
    var Chart = window.Chart;
    var cats = Object.keys(categoryCounts);
    var values = cats.map(function (c) { return categoryCounts[c]; });
    var colors = cats.map(function (c, i) { return colorFor(c, i); });

    new Chart(document.getElementById("chart-doughnut"), {
      type: "doughnut",
      data: {
        labels: cats,
        datasets: [{ data: values, backgroundColor: colors,
                     borderColor: cssVar("--surface"), borderWidth: 2 }]
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { position: "bottom", labels: { boxWidth: 12 } } }
      }
    });

    new Chart(document.getElementById("chart-bars"), {
      type: "bar",
      data: {
        labels: cats,
        datasets: [{ label: "Events", data: values, backgroundColor: colors,
                     borderRadius: 2, maxBarThickness: 42 }]
      },
      options: {
        indexAxis: "y", responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: { x: { beginAtZero: true, ticks: { precision: 0 } } }
      }
    });
  }

  function renderTimeline(timeline, note, onHidden) {
    var canvas = document.getElementById("chart-timeline");
    if (!timeline.length) {
      canvas.closest(".chart-box").hidden = true;
      var noteEl = document.getElementById("timeline-hidden");
      noteEl.hidden = false;
      noteEl.textContent = note || "No timeline: this file has no usable timestamps.";
      if (onHidden) { onHidden(); }
      return;
    }
    new Chart(canvas, {
      type: "line",
      data: {
        labels: timeline.map(function (p) { return p.time; }),
        datasets: [{
          label: "Attack events",
          data: timeline.map(function (p) { return p.count; }),
          borderColor: cssVar("--accent"), backgroundColor: cssVar("--accent"),
          pointRadius: 2, tension: 0.15, fill: false
        }]
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: { y: { beginAtZero: true, ticks: { precision: 0 } } }
      }
    });
  }

  function renderScatter(explore) {
    var groups = {};
    explore.points.forEach(function (point) {
      (groups[point.category] = groups[point.category] || []).push({ x: point.x, y: point.y });
    });
    new Chart(document.getElementById("chart-explore"), {
      type: "scatter",
      data: {
        datasets: Object.keys(groups).map(function (cat, i) {
          return {
            label: cat,
            data: groups[cat],
            backgroundColor: colorFor(cat, i),
            pointRadius: 2.5,
            pointOpacity: 0.65
          };
        })
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { position: "bottom", labels: { boxWidth: 12 } } },
        scales: {
          x: { title: { display: true, text: "projection axis 1" }, ticks: { display: false } },
          y: { title: { display: true, text: "projection axis 2" }, ticks: { display: false } }
        }
      }
    });
  }

  window.CyberLensCharts = {
    init: init,
    colorFor: colorFor,
    renderCategoryCharts: renderCategoryCharts,
    renderTimeline: renderTimeline,
    renderScatter: renderScatter
  };
})();
