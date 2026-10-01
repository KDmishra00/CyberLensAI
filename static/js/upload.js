/* Upload page: drop zone, explicit Upload button, progress bar, honest status text.
   All user-derived strings go through textContent - never innerHTML. */
(function () {
  "use strict";

  var MAX_BYTES = 20 * 1024 * 1024;
  var ALLOWED = [".csv", ".xlsx", ".log"];

  var form = document.getElementById("upload-form");
  var dropzone = document.getElementById("dropzone");
  var input = document.getElementById("file-input");
  var chooseBtn = document.getElementById("choose-btn");
  var uploadBtn = document.getElementById("upload-btn");
  var fileInfo = document.getElementById("file-info");
  var fileName = document.getElementById("file-name");
  var fileMeta = document.getElementById("file-meta");
  var typeWarning = document.getElementById("file-type-warning");
  var track = document.getElementById("progress-track");
  var bar = document.getElementById("progress-bar");
  var status = document.getElementById("upload-status");
  var actionsRow = document.querySelector(".upload-actions");

  var file = null;
  var uploadedId = null;

  function humanSize(bytes) {
    if (bytes < 1024 * 1024) {
      return Math.max(1, Math.round(bytes / 1024)) + " KB";
    }
    return (bytes / (1024 * 1024)).toFixed(1) + " MB";
  }

  function setStatus(text, isOk) {
    status.textContent = text;
    status.classList.toggle("status-ok", Boolean(isOk));
  }

  function setFile(f) {
    uploadedId = null;
    file = f || null;
    actionsRow.querySelector(".btn-continue") && actionsRow.querySelector(".btn-continue").remove();
    if (!file) {
      fileInfo.hidden = true;
      uploadBtn.disabled = true;
      return;
    }
    fileName.textContent = file.name;
    fileMeta.textContent = humanSize(file.size) + " selected";
    var ext = file.name.slice(file.name.lastIndexOf(".")).toLowerCase();
    var known = ALLOWED.indexOf(ext) !== -1;
    typeWarning.hidden = known;
    typeWarning.textContent = known ? "" :
      "Heads up: that does not look like a format CyberLens reads. Use .csv, .xlsx or .log - the server will check properly.";
    fileInfo.hidden = false;
    uploadBtn.disabled = false;
    setStatus("Selected. Press Upload when you are ready.");
  }

  dropzone.addEventListener("click", function () { input.click(); });
  dropzone.addEventListener("keydown", function (event) {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      input.click();
    }
  });
  chooseBtn.addEventListener("click", function () { input.click(); });
  input.addEventListener("change", function () { setFile(input.files[0]); });

  ["dragover", "dragenter"].forEach(function (name) {
    dropzone.addEventListener(name, function (event) {
      event.preventDefault();
      dropzone.classList.add("dragover");
    });
  });
  ["dragleave", "drop"].forEach(function (name) {
    dropzone.addEventListener(name, function (event) {
      event.preventDefault();
      dropzone.classList.remove("dragover");
    });
  });
  dropzone.addEventListener("drop", function (event) {
    var dropped = event.dataTransfer && event.dataTransfer.files && event.dataTransfer.files[0];
    if (dropped) {
      setFile(dropped);
    }
  });

  form.addEventListener("submit", function (event) {
    event.preventDefault();
    if (!file || uploadBtn.disabled) {
      return;
    }
    if (file.size > MAX_BYTES) {
      setStatus("That file is " + humanSize(file.size) + ". The limit is 20 MB.");
      return;
    }
    uploadBtn.disabled = true;
    chooseBtn.disabled = true;
    track.hidden = false;
    bar.style.width = "0";

    var xhr = new XMLHttpRequest();
    xhr.open("POST", "/api/upload");
    xhr.upload.addEventListener("progress", function (progress) {
      if (progress.lengthComputable) {
        var pct = Math.round((progress.loaded / progress.total) * 100);
        bar.style.width = pct + "%";
        setStatus(pct < 100 ? "Uploading\u2026 " + pct + "%" : "Checking the file\u2026");
      }
    });
    xhr.addEventListener("load", function () {
      var data = {};
      try { data = JSON.parse(xhr.responseText); } catch (err) { /* handled below */ }
      if (xhr.status === 200 && data.analysis_id) {
        uploadedId = data.analysis_id;
        bar.style.width = "100%";
        setStatus("Uploaded. Ready to preview.", true);
        var link = document.createElement("a");
        link.href = "/preview/" + uploadedId;
        link.className = "btn btn-primary btn-continue";
        link.textContent = "Continue to preview";
        actionsRow.appendChild(link);
      } else {
        track.hidden = true;
        uploadBtn.disabled = false;
        chooseBtn.disabled = false;
        setStatus(data.error || "The upload failed. Nothing was stored.", false);
      }
    });
    xhr.addEventListener("error", function () {
      track.hidden = true;
      uploadBtn.disabled = false;
      chooseBtn.disabled = false;
      setStatus("The upload could not reach the server. Is the app still running?");
    });

    var body = new FormData();
    body.append("file", file);
    xhr.send(body);
  });
})();
