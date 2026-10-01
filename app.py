"""CyberLens AI - Flask entry point.

Routes are thin: they validate, call core modules, and shape JSON/HTML.
Analysis state lives in a small in-memory dict keyed by a random id; files
live in tmp/<id>/ and are swept when older than an hour.
"""
from __future__ import annotations

import math
import os
import shutil
import threading
import time
from datetime import datetime, timezone

import pandas as pd
from flask import Flask, jsonify, redirect, render_template, request, send_file

import config
from core import analyzer, parser, preprocess, report, security, stats
from core.upload import UploadError, analysis_dir, new_analysis_id, save_upload
from core.report import build_summary_paragraphs, severity_rule_text

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = config.MAX_CONTENT_LENGTH
app.json.sort_keys = False

# analysis_id -> {filename, size, uploaded_at, detected_type, preview, status,
#                 stage, error, results, df}
ANALYSES: dict[str, dict] = {}
_STORE_LOCK = threading.Lock()
_PIPELINE_LOCKS: dict[str, threading.Lock] = {}


def _store_get(analysis_id: str) -> dict | None:
    with _STORE_LOCK:
        return ANALYSES.get(analysis_id)


def _store_update(analysis_id: str, **fields) -> None:
    with _STORE_LOCK:
        entry = ANALYSES.get(analysis_id)
        if entry is not None:
            entry.update(fields)


# --- temporary storage sweep -------------------------------------------------

def _sweep_once() -> None:
    now = time.time()
    if not os.path.isdir(config.TMP_DIR):
        return
    for name in os.listdir(config.TMP_DIR):
        folder = os.path.join(config.TMP_DIR, name)
        try:
            if now - os.path.getmtime(folder) > config.TMP_MAX_AGE_SECONDS:
                shutil.rmtree(folder, ignore_errors=True)
                with _STORE_LOCK:
                    ANALYSES.pop(name, None)
        except OSError:
            continue


def _sweep_loop() -> None:
    while True:
        time.sleep(config.CLEANUP_INTERVAL_SECONDS)
        _sweep_once()


# --- security headers --------------------------------------------------------

@app.after_request
def _security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'"
    )
    response.headers["Referrer-Policy"] = "no-referrer"
    if not request.path.startswith("/static/"):
        response.headers["Cache-Control"] = "no-store"
    return response


# --- error pages -------------------------------------------------------------

@app.errorhandler(413)
def _too_large(_error):
    message = "That file is larger than the 20 MB limit."
    if request.path.startswith("/api/"):
        return jsonify(error=message), 413
    return render_template("upload.html", error=message), 413


@app.errorhandler(404)
def _not_found(_error):
    return (
        render_template("error.html",
                        title="Page not found",
                        message="That link does not point at anything. "
                                "It may belong to an analysis that has expired or been deleted."),
        404,
    )


@app.errorhandler(500)
def _server_error(_error):
    if request.path.startswith("/api/"):
        return jsonify(error="Something went wrong on our side. Nothing was saved."), 500
    return render_template("error.html",
                           title="Something went wrong",
                           message="An unexpected error occurred. Your uploaded file was never modified."), 500


# --- pages -------------------------------------------------------------------

@app.route("/")
def home():
    return render_template("index.html", model_ok=analyzer.HAS_MODEL)


@app.route("/upload")
def upload_page():
    return render_template("upload.html", model_ok=analyzer.HAS_MODEL, error=None)


@app.route("/about")
def about_page():
    return render_template("about.html", model_ok=analyzer.HAS_MODEL)


@app.route("/preview/<analysis_id>")
def preview_page(analysis_id):
    entry = _store_get(analysis_id)
    if entry is None:
        return redirect("/upload")
    return render_template("preview.html", analysis_id=analysis_id,
                           filename=entry["filename"], model_ok=analyzer.HAS_MODEL)


@app.route("/dashboard/<analysis_id>")
def dashboard_page(analysis_id):
    entry = _store_get(analysis_id)
    if entry is None:
        return redirect("/upload")
    if entry["status"] != "done":
        return redirect(f"/preview/{analysis_id}")
    return render_template("dashboard.html", analysis_id=analysis_id,
                           filename=entry["filename"], model_ok=analyzer.HAS_MODEL)


@app.route("/report/<analysis_id>")
def report_page(analysis_id):
    entry = _store_get(analysis_id)
    if entry is None:
        return redirect("/upload")
    if entry["status"] != "done":
        return render_template("error.html", title="No report yet",
                               message="A report exists only after a completed analysis. "
                                       "Run the analysis first, then come back here."), 404
    results = entry["results"]
    return render_template("report.html", analysis_id=analysis_id,
                           filename=entry["filename"], results=results,
                           mitigations=security.mitigations_for_categories(
                               list(results["category_counts"].keys())),
                           severity_rule=severity_rule_text(), model_ok=analyzer.HAS_MODEL)


# --- API ---------------------------------------------------------------------

@app.route("/api/upload", methods=["POST"])
def api_upload():
    if "file" not in request.files:
        return jsonify(error="No file was selected. Choose a file first."), 400
    analysis_id = new_analysis_id()
    try:
        path, original_name, size = save_upload(request.files["file"], analysis_id)
    except UploadError as exc:
        shutil.rmtree(analysis_dir(analysis_id), ignore_errors=True)
        return jsonify(error=str(exc)), 400

    # Parse immediately so the preview and its warnings are honest up front.
    try:
        df, meta = parser.parse_file(path, os.path.splitext(path)[1], original_name)
    except parser.ParseError as exc:
        shutil.rmtree(analysis_dir(analysis_id), ignore_errors=True)
        return jsonify(error=str(exc)), 400

    entry = {
        "filename": original_name,
        "size": size,
        "uploaded_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "detected_type": meta.get("detected_type", ""),
        "meta": meta,
        "status": "ready",
        "stage": "",
        "error": None,
        "results": None,
        "df": None,
    }
    entry["preview"] = _build_preview(df, meta, original_name, size)
    with _STORE_LOCK:
        ANALYSES[analysis_id] = entry
        _PIPELINE_LOCKS[analysis_id] = threading.Lock()
    return jsonify(analysis_id=analysis_id, filename=original_name,
                   size=size, status="ready")


@app.route("/api/preview/<analysis_id>")
def api_preview(analysis_id):
    entry = _store_get(analysis_id)
    if entry is None:
        return jsonify(error="This analysis has expired or was deleted. Upload the file again."), 404
    preview = dict(entry["preview"])
    preview["analysis_id"] = analysis_id
    preview["status"] = entry["status"]
    return jsonify(preview)


@app.route("/api/analyze/<analysis_id>", methods=["POST"])
def api_analyze(analysis_id):
    entry = _store_get(analysis_id)
    if entry is None:
        return jsonify(error="This analysis has expired or was deleted. Upload the file again."), 404
    if not analyzer.HAS_MODEL:
        return jsonify(error="Model not found. Run `python train_model.py` first, then restart the app."), 503
    if entry["status"] == "done":
        return jsonify(status="done")

    lock = _PIPELINE_LOCKS.get(analysis_id)
    if lock is None or not lock.acquire(blocking=False):
        return jsonify(status="already_running"), 202
    try:
        if entry["status"] == "running":
            return jsonify(status="already_running"), 202
        entry.update(status="running", stage="Preparing", error=None)
    finally:
        lock.release()

    thread = threading.Thread(target=_run_pipeline, args=(analysis_id,), daemon=True)
    thread.start()
    return jsonify(status="started")


@app.route("/api/progress/<analysis_id>")
def api_progress(analysis_id):
    entry = _store_get(analysis_id)
    if entry is None:
        return jsonify(status="unknown", error="expired"), 404
    return jsonify(status=entry["status"], stage=entry.get("stage", ""),
                   error=entry.get("error"))


@app.route("/api/results/<analysis_id>")
def api_results(analysis_id):
    entry = _store_get(analysis_id)
    if entry is None:
        return jsonify(error="This analysis has expired or was deleted."), 404
    if entry["status"] != "done":
        return jsonify(error="Analysis is not finished yet.", status=entry["status"]), 409
    results = entry["results"]
    payload = dict(results)
    payload["model_accuracy"] = analyzer.metrics.get("accuracy") if analyzer.metrics else None
    payload["model_trained_at"] = analyzer.metrics.get("trained_at") if analyzer.metrics else None
    payload["mitigations"] = security.mitigations_for_categories(
        list(results["category_counts"].keys()))
    return jsonify(payload)


@app.route("/api/detections/<analysis_id>")
def api_detections(analysis_id):
    """Server-side filter / sort / pagination for the detections table."""
    entry = _store_get(analysis_id)
    if entry is None or entry["status"] != "done":
        return jsonify(error="Analysis is not finished yet."), 409

    df: pd.DataFrame = entry["df"]
    rows = df[df["is_anomaly"]].copy()

    category = request.args.get("category", "")
    severity = request.args.get("severity", "")
    query = request.args.get("q", "").strip().lower()
    if category:
        rows = rows[rows["predicted_category"] == category]
    if severity:
        rows = rows[rows["severity"] == severity]
    if query:
        haystack = (rows["event"].fillna("").str.lower() + " " +
                    rows["src_ip"].fillna("").str.lower() + " " +
                    rows["username"].fillna("").str.lower())
        rows = rows[haystack.str.contains(query, regex=False)]

    sort_key = request.args.get("sort", "severity")
    ascending = request.args.get("dir", "desc") == "asc"
    if sort_key == "severity":
        rank = rows["severity"].map({n: i for i, n in enumerate(config.SEVERITY_LEVELS)}).fillna(-1)
        rows = rows.assign(_rank=rank, _conf=rows["confidence"]).sort_values(
            ["_rank", "_conf"], ascending=ascending)
    elif sort_key == "time":
        rows = rows.sort_values("timestamp", ascending=ascending, na_position="last")
    elif sort_key == "confidence":
        rows = rows.sort_values("confidence", ascending=ascending)
    elif sort_key == "src_ip":
        rows = rows.sort_values("src_ip", ascending=ascending)
    elif sort_key == "category":
        rows = rows.sort_values("predicted_category", ascending=ascending)

    total = int(len(rows))
    per_page = 25
    page = max(1, int(request.args.get("page", 1) or 1))
    last_page = max(1, math.ceil(total / per_page))
    page = min(page, last_page)
    chunk = rows.iloc[(page - 1) * per_page: page * per_page]

    return jsonify(
        total=total, page=page, last_page=last_page,
        rows=[{
            "row_id": int(r.row_id),
            "timestamp": r.timestamp.strftime("%Y-%m-%d %H:%M:%S") if pd.notna(r.timestamp) else None,
            "src_ip": r.src_ip,
            "username": r.username or "",
            "category": r.predicted_category,
            "severity": r.severity,
            "confidence": round(float(r.confidence), 3),
            "event": str(r.event)[:400],
        } for r in chunk.itertuples(index=False)]
    )


@app.route("/report/<analysis_id>/download")
def report_download(analysis_id):
    entry = _store_get(analysis_id)
    if entry is None:
        return redirect("/upload")
    if entry["status"] != "done":
        return render_template("error.html", title="No report yet",
                               message="A report exists only after a completed analysis."), 404
    pdf_path = os.path.join(analysis_dir(analysis_id), "incident_report.pdf")
    report.generate_report_pdf(entry["results"],
                               {"filename": entry["filename"],
                                "summary_paragraphs": entry["results"]["summary_paragraphs"]},
                               pdf_path)
    return send_file(pdf_path, as_attachment=True,
                     download_name=f"cyberlens_report_{analysis_id[:8]}.pdf",
                     mimetype="application/pdf")


@app.route("/api/delete/<analysis_id>", methods=["POST"])
def api_delete(analysis_id):
    try:
        folder = analysis_dir(analysis_id)
    except UploadError:
        return jsonify(error="Unknown analysis id."), 404
    shutil.rmtree(folder, ignore_errors=True)
    with _STORE_LOCK:
        ANALYSES.pop(analysis_id, None)
        _PIPELINE_LOCKS.pop(analysis_id, None)
    return jsonify(status="deleted")


# --- pipeline ----------------------------------------------------------------

def _run_pipeline(analysis_id: str) -> None:
    entry = _store_get(analysis_id)
    if entry is None:
        return
    try:
        path = os.path.join(analysis_dir(analysis_id), "upload" +
                            os.path.splitext(entry["filename"].lower())[1])

        _store_update(analysis_id, stage="Cleaning data")
        df, _ = parser.parse_file(path, os.path.splitext(path)[1], entry["filename"])
        clean, summary = preprocess.preprocess(df)
        if clean.empty:
            raise ValueError("After cleaning, no rows were left to analyse.")

        _store_update(analysis_id, stage="Running model")
        predicted = analyzer.predict(clean)
        warning = analyzer.reliability_warning(predicted)

        _store_update(analysis_id, stage="Assigning severity")
        predicted = security.assign_severity(predicted)

        _store_update(analysis_id, stage="Summarising")
        results = stats.compute_stats(predicted, summary)
        results["reliability_warning"] = warning
        results["generated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        results["summary_paragraphs"] = build_summary_paragraphs(results, entry["filename"])
        results["explore"] = _explore_coords(predicted)
        results["detected_type"] = entry["detected_type"]

        _store_update(analysis_id, status="done", stage="", results=results, df=predicted)
    except Exception as exc:  # noqa: BLE001 - any failure must reach the UI
        _store_update(analysis_id, status="failed", stage="",
                      error=f"Analysis failed: {exc}")


def _build_preview(df: pd.DataFrame, meta: dict, filename: str, size: int) -> dict:
    """Fast preview payload: first rows, column roles, missing counts, stats."""
    head = df.head(20).copy()
    if "timestamp" in head.columns:
        head["timestamp"] = head["timestamp"].astype(str).replace("NaT", "")

    roles = {
        "row_id": "row", "timestamp": "timestamp", "src_ip": "IP address",
        "dst_ip": "IP address", "dst_port": "numeric", "username": "username",
        "event": "event text", "bytes": "numeric", "duration": "numeric",
        "status": "status", "label_original": "label in the file (not used by the model)",
    }
    columns = []
    for col in head.columns:
        role = roles.get(col, "numeric" if pd.api.types.is_numeric_dtype(df[col]) else "text")
        columns.append({"name": str(col), "role": role,
                        "missing": int(df[col].isna().sum())})

    numeric_stats = []
    for col in df.columns:
        if pd.api.types.is_numeric_dtype(df[col]) and df[col].notna().any():
            series = pd.to_numeric(df[col], errors="coerce")
            numeric_stats.append({
                "name": str(col), "count": int(series.notna().sum()),
                "mean": round(float(series.mean()), 2),
                "min": round(float(series.min()), 2),
                "max": round(float(series.max()), 2),
            })

    duplicate_count = int(df.duplicated().sum())
    if "timestamp" in df.columns and "event" in df.columns:
        key = df["timestamp"].notna() & df["event"].notna()
        duplicate_count += int(df[key].duplicated(subset=["timestamp", "src_ip", "event"]).sum())

    warnings = []
    mapping = meta.get("column_mapping", {})
    if mapping:
        renamed = ", ".join(f"'{orig}' read as {canon}" for canon, orig in mapping.items())
        warnings.append(f"Column names were mapped to canonical fields: {renamed}.")
    if meta.get("note"):
        warnings.append(meta["note"])
    if meta.get("failed_lines"):
        warnings.append(
            f"{meta['failed_lines']} line(s) did not match any known log format and were "
            "kept with the text that could be salvaged.")
    rate = meta.get("parse_success_rate")
    if rate is not None:
        pct = round(rate * 100, 1)
        verdict = "meets" if rate >= 0.95 else "is below"
        warnings.append(f"Parse success rate {pct}% (target is 95%; this file {verdict} it).")

    return {
        "filename": filename,
        "size": size,
        "size_human": f"{size / 1024:.0f} KB" if size < 1024 * 1024 else f"{size / (1024 * 1024):.1f} MB",
        "detected_type": meta.get("detected_type", ""),
        "row_count": int(meta.get("row_count", len(df))),
        "column_count": int(len(df.columns)),
        "parse_success_rate": rate,
        "formats": meta.get("formats", {}),
        "columns": columns,
        "rows": head.astype(object).where(head.notna(), "").to_dict("records"),
        "numeric_stats": numeric_stats,
        "duplicates_detected": duplicate_count,
        "warnings": warnings,
    }


def _explore_coords(df: pd.DataFrame) -> dict | None:
    """2-D PCA over TF-IDF + numeric features for the Explore scatter plot."""
    try:
        from sklearn.decomposition import PCA
        from sklearn.feature_extraction.text import TfidfVectorizer
        from scipy import sparse

        sample = df.sample(n=min(2_000, len(df)), random_state=0)
        numeric = sample[config.MODEL_NUMERIC_FEATURES].fillna(0).to_numpy(dtype="float64")
        text = sample["event_clean"].fillna("").astype(object)
        tfidf = TfidfVectorizer(ngram_range=(1, 2), min_df=2, max_features=300)
        text_matrix = tfidf.fit_transform(text)
        matrix = sparse.hstack([text_matrix, sparse.csr_matrix(numeric)]).tocsr()
        coords = PCA(n_components=2, random_state=0).fit_transform(matrix.toarray())
        return {
            "points": [{"x": round(float(x), 3), "y": round(float(y), 3),
                        "category": cat} for (x, y), cat in
                       zip(coords, sample["predicted_category"])],
        }
    except Exception:  # Explore is optional; never break the dashboard over it
        return None


# start the tmp sweep daemon
_sweeper = threading.Thread(target=_sweep_loop, daemon=True)
_sweeper.start()


if __name__ == "__main__":
    os.makedirs(config.TMP_DIR, exist_ok=True)
    print(f"CyberLens AI running at http://{config.HOST}:{config.PORT}")
    app.run(host=config.HOST, port=config.PORT, debug=config.DEBUG)
