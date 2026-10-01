# CyberLens AI — Viva Q&A Sheet

Kuldeep Mishra & Samay Shakya · Manipal University Jaipur

One-line architecture: **Flask app → file validation → parser → pandas preprocessing → scikit-learn classifier → severity/mitigation layer → Chart.js dashboard → ReportLab PDF.** Everything offline, single user, no database.

> Every number below is verifiable in `models/metrics.json`, `config.py`, or the README. If an examiner checks, it matches.
> Current verified state: **23/23 pytest tests pass.**

---

## 1. Big-picture questions

**Q. Walk me through what happens from upload to report.**
1. Upload page accepts `.csv`, `.xlsx`, `.log` up to 20 MB.
2. `core/upload.py` validates *before anything reads the content*: extension allowlist, size, decodable text, and for Excel a real ZIP structure with **no macros** (`vbaProject.bin` is refused) and a 200 MB decompressed-XML cap (zip-bomb guard).
3. File is stored at `tmp/<random 32-hex id>/`, and the browser is redirected to a preview built from the *parsed* data.
4. `core/parser.py` turns any of the three formats into one canonical DataFrame (timestamp, src_ip, event text, bytes, dst_port, username…), using fuzzy column-name mapping for CSV/XLSX and four log extractors (syslog, Apache combined, ISO, generic).
5. "Run analysis" triggers `core/preprocess.py`: dedupe, timestamp normalisation, missing-value handling, and derived behavioural features (per-IP event count, ±30 s rate, distinct ports/users, failure ratio…).
6. `core/analyzer.py` runs the saved sklearn pipeline in 20k-row batches → category + probability per row.
7. `core/security.py` assigns severity from a documented rule and looks up mitigations from `data/mitigations.json`.
8. `core/stats.py` computes totals, breakdowns, top IPs/ports and an auto-bucketed timeline; the dashboard renders them with Chart.js.
9. "Download PDF" renders the same story through `core/report.py` (ReportLab) with a summary, charts and mitigations.
10. "Delete my data" wipes the folder immediately; anything left is swept after 60 minutes.

**Q. Is this AI? It's just a linear model.**
The intelligence is the trained text-and-behaviour classifier: TF-IDF over event text *plus* behavioural numerics feeding a logistic regression that assigns one of six attack categories with a calibrated confidence, which then drives severity. We deliberately kept the model class simple and spent the effort on the pipeline — corpus/parser alignment, features, thresholds — which is where accuracy actually came from (97.29% held-out, vs. a much weaker model before we aligned the corpus with what the parser extracts).

**Q. Why is this safe to demo? What are its boundaries?**
It reads files, never executes them; never touches a live network; refuses macros, oversized and binary files; deletes data on request and sweeps after an hour. Boundaries we state up front: seven classes only (Normal + 6 attacks), trained on synthetic data, English/IPv4 formats, single user, Flask dev server. Anything outside scope is reported as Normal rather than guessed.

---

## 2. Technology choices

**Q. Why Flask and not Django / FastAPI?**
The spec is a small, single-user, form-and-file-upload web tool. Django brings an ORM, admin and auth we explicitly don't want (a database was out of scope); FastAPI's strength is async APIs, and our workload is a blocking, CPU-bound batch job. Flask gives us routing, Jinja templating and error handlers in one small file (`app.py`, ~20 KB) with no magic — easy to defend line by line in a viva.

**Q. Why pandas?**
Three formats must collapse into one canonical schema, then get timestamp-normalised, deduplicated and enriched with derived per-IP features. That is exactly vectorised DataFrame work — doing it in pure Python over 500k-row files would be far slower and buggier. We also hit and fixed real pandas-3 behaviours (see §5), which we can discuss concretely.

**Q. Why scikit-learn rather than deep learning (LSTM/CNN/transformer)?**
- The signal is lexical and behavioural, not deep-semantic; TF-IDF + logistic regression is the honest, strong baseline for short structured log lines.
- **Train in seconds, run offline on a laptop** — the brief requires a standalone offline app; no GPU, no model server.
- **Smooth probabilities** — the severity rule (±1 level at 0.90 / 0.65 confidence) and the 0.55 anomaly threshold need reliable probabilities; logistic regression gives them directly.
- **Explainability** — we can inspect coefficients and say *why* an event was flagged; important for a security tool and for this viva.
- Deployment is one joblib file — no runtime dependency beyond sklearn itself.

**Q. Why TF-IDF and not word embeddings?**
Log lines are templated: tokens like `Failed password`, `SELECT`, port numbers carry the class signal. TF-IDF word 1–2-grams captures the phrasing; `char_wb` 3–5-grams catches obfuscation variants (`' OR 1=1`, base64 blobs) without a vocabulary to train. Embeddings would add a large model file and network/pretraining assumptions for little gain on templated text, and would hurt our fully-offline requirement.

**Q. Why logistic regression and not random forest / SVM?**
Trains in ~5 s on the sparse stacked matrix; gives calibrated probabilities; regularisation (C=5.0) is one interpretable knob. A random forest on sparse TF-IDF is slow and memory-hungry and yields less smooth probabilities; an SVM needs Platt scaling for probabilities. Held-out accuracy: **97.29%**, per-class F1 between 0.930 (Privilege Escalation) and 0.982 (Port Scan) — recorded in `models/metrics.json`.

**Q. Why Chart.js, vendored, and not a React dashboard or CDN script?**
The brief is a minimalist offline app: no build step, no npm, no CDN. Chart.js 4.4.9 is one file (`static/vendor/chart.umd.min.js`) covering doughnut, bar, timeline and scatter. Vendoring keeps our strict CSP (`script-src 'self'` — no inline scripts, no external origins) intact and the app genuinely network-free. React would require a toolchain for zero benefit at this size.

**Q. Why ReportLab and not matplotlib or wkhtmltopdf?**
The PDF is a structured document — headings, tables, summary paragraphs, a timeline chart — not a plot image. ReportLab's Platypus does exactly that in pure Python, offline, with no headless browser to install. We drew the timeline ourselves with ReportLab graphics (`PolyLine`) rather than adding matplotlib as a dependency (a decision recorded in the README).

**Q. Why joblib?**
It's the canonical sklearn persistence format for pipelines containing sparse matrices and NumPy arrays — one file, atomic to load, version-stamped alongside `metrics.json`. Model is loaded once at import; if it's missing, the app still boots and shows an honest "model not loaded" banner instead of crashing.

**Q. Why pytest? Why 23 tests?**
The pipeline is too interlocked to verify by clicking. pytest's fixtures give us a Flask test client exercising the real HTTP flow. The 23 tests cover the rejection paths (extension, content, macros, oversize), each log format's field extraction, timestamp normalisation (epoch, no-year syslog), dedupe, fuzzy column mapping, model load/predict, severity bounds, stats sanity (attacks + normal = total), the clean-file empty state, PDF validity, and a full upload → analyse → results → detections → PDF → delete round trip. Two tests print the measured log parse success rate: **100% on both samples** (target ≥95%).

**Q. Why Jinja2 server-side rendering instead of a SPA?**
Six pages, no routing state, no login. Server-rendered Jinja with autoescape on is smaller, faster to load and safer by default. The four small JS files (upload, preview, charts, dashboard) do progressive enhancement only — fetch, render tables, draw charts — and use `textContent`, never `innerHTML`.

---

## 3. Design decisions (the "why" behind the details)

**Q. Why no database?**
State is one analysis at a time for one user: a dict keyed by a random 32-hex id, plus `tmp/<id>/` on disk. A DB would add a schema, migrations and concurrency we don't have. Trade-off we admit: a server restart forgets dashboards (files remain until swept/deleted). Documented in the README as a deliberate scope cut.

**Q. Why port 5001?**
macOS AirPlay Receiver occupies 5000 on modern macOS, so the server would silently conflict on every student Mac. It's configurable via `CYBERLENS_PORT`.

**Q. Why a 0.55 anomaly threshold?**
Below ~0.55 confidence, an "attack" prediction is more likely noise than signal; those rows count as Normal and are reported separately as low-confidence, so the tool under-reports rather than inflates attack counts. 0.65 and 0.90 are the severity down/up adjustment points. All three live in `config.py` with comments.

**Q. Justify the severity rule.**
Base severity per category (Malware=Critical; SQLi/PrivEsc/DoS=High; Brute Force=Medium; Port Scan=Low), then at most one step up (confidence ≥0.90, or the same source IP produced ≥20 attack events — a sustained campaign) and one step down (confidence <0.65), clamped to exactly Low/Medium/High/Critical. It's deterministic, explainable on every report, and no LLM-style hand-waving — the rule text is printed on the report itself.

**Q. Why exclude ephemeral ports (≥49152) from "top targeted ports"?**
Normal client traffic uses random high source ports; without the filter, SSH's ephemeral ports dominate the list and bury the actual scanned service ports.

**Q. Why is "Analyse" only available after preview?**
The preview is rendered *from the parsed DataFrame*, so a file that can't be parsed never reaches an Analyse button — the enable logic (`preview.js`) enforces the pipeline order in the UI, not just in the backend.

**Q. Why is parse success rate defined as timestamp-or-IP?**
It's the honest testable criterion that an event was actually extracted with something usable (a time or a source); both sample logs measure 100%.

**Q. What happens with a file that has weird column names?**
`COLUMN_ALIASES` fuzzy-maps variants (e.g. `src_addr`, `source_ip`, `client` → src_ip). Deliberately conservative: first matching alias wins, each original column maps to at most one canonical field; unmapped numerics ride along as display extras (capped at 20) but never silently become model features.

**Q. Your training data is synthetic — isn't that a weakness?**
Yes, and we say so on the dashboard, the report and the README: 97.29% is performance on synthetic data and says nothing about real-world accuracy. Given the offline/no-dataset constraint of the brief, a seeded, reproducible corpus (~20k rows, 3% label noise, per-IP behavioural patterns) was the defensible choice; the README documents exactly how to swap in CIC-IDS/UNSW-NB15 and retrain.

**Q. Why is corpus↔parser alignment "the thing that matters"?**
Our first model scored poorly because the corpus was written differently from what the parser extracts at inference (IPs, empty usernames, ports). We rewrote `corpus.py` to mirror the parser's extraction exactly — train/serve skew eliminated — and accuracy jumped to 97.3%. Good lesson: in applied ML, feature consistency between training and inference beats fancier models.

---

## 4. Security questions

**Q. You built a security tool — how do you secure it?**
- **Uploads are data, never code**: nothing executed, original file never modified, nothing served back to the browser.
- **Validation before parsing**: extension allowlist, 20 MB cap, decodable-text check; XLSX must be a real ZIP with no macros; 200 MB decompressed cap and 500k-row cap against zip bombs/runaway files.
- **Browser hardening**: CSP `script-src 'self'`; all user-derived text rendered with `textContent` (never `innerHTML`); Jinja autoescape on; `X-Content-Type-Options: nosniff`; restrictive `Referrer-Policy`; `Cache-Control: no-store` on result pages.
- **PDF formula injection**: every exported table cell starting with `=`, `+`, `-` or `@` gets a `'` prefix (`_cell()` in `core/report.py`) — a malicious IP string can't become a formula when the report is pasted into Excel.
- **Data lifecycle**: "Delete my data" removes the folder immediately; background sweep after 60 min.

**Q. Why the CSP? Doesn't it complicate things?**
It forbids inline scripts and external origins, which kills whole XSS exploit classes. Cost: no inline `<script>` — the analysis id travels via `<body data-analysis-id="…">` and JS reads `document.body.dataset.analysisId`. A small, deliberate price.

**Q. Path traversal on the analysis id?**
The id is a random 32-hex string generated server-side; lookups validate the id format and resolve inside `tmp/`. There is no user-controlled path component.

**Q. Is the Flask dev server safe?**
It's a deliberate, documented limitation: single-user, bound to 127.0.0.1, debug off. Production would sit behind gunicorn + a reverse proxy — one line in the README's limitations.

---

## 5. "War stories" — debugging questions examiners love

**Q. Tell me about a real bug you fixed.**
*pandas 3 + nullable dtypes:* `pd.to_numeric` on string-dtype columns returns nullable `Float64`; `pd.NA` in a boolean mask then silently drops rows inside `.where()` — rows vanished with no error. Fix: coerce with `.astype("float64")` before masking.
*Timestamp parsing:* pandas `format="mixed"` parses no-year syslog dates (`Aug 14 10:22:31`) as **year 1**, and needs an explicit route (`%b %d %H:%M:%S` + current-year repair); Apache's `%d/%b/%Y:%H:%M:%S %z` gets its own explicit route. Epoch handling is resolution-dependent, so the ±30 s rate window is computed as `(ts − epoch) // Timedelta(seconds=1)` instead of `.astype("int64")`.

**Q. Another one — something non-obvious.**
Flask caches rendered templates when debug is off, so template edits appeared to "do nothing" until restart — twice. And an earlier `/api/results/undefined` 404 came from the analysis id not reaching the JS; the CSP had blocked inline scripts, so we moved the id into a `data-` attribute.

**Q. How did you verify the whole thing?**
23 pytest tests including a full HTTP round trip, then a live browser pass: all pages HTTP 200, zero console errors, light/dark themes and 375 px width checked, rejection paths exercised, delete + sweep verified, PDF opens as a valid 2-page document.

**Q. What are the limits? (Say these before you're asked.)**
Synthetic-only training; seven classes; English/IPv4; single user; in-memory state lost on restart; Flask dev server; first XLSX sheet only; timeline sub-minute bursts not separable. Honest limits are in the README and spoken on the dashboard.

---

## 6. Numbers to memorise

| Fact | Value |
|---|---|
| Held-out accuracy | **97.29%** (20,117 corpus rows; 16,093 train / 4,024 test) |
| Per-class F1 range | 0.930 (Privilege Escalation) – 0.982 (Port Scan) |
| Model | TF-IDF word 1–2g + char_wb 3–5g + 12 scaled numerics → LogisticRegression C=5.0 |
| Training time | ~5 seconds |
| Upload limit | 20 MB; 500k rows; 200 MB xlsx decompressed cap |
| Thresholds | anomaly 0.55 · severity −1 < 0.65 · +1 ≥ 0.90 · repeat-IP ≥ 20 events |
| Severity ladder | Low / Medium / High / Critical |
| Retention | Delete on request; auto-sweep after 60 min |
| Port | 5001 (5000 = macOS AirPlay) |
| Tests | 23 passing · log parse rate 100% on both samples (target ≥95%) |
| Sample results | auth log: 322 attacks (320 Brute Force)/4,850 · web log: 559 (DoS 358, Port Scan 131, SQLi 70)/9,567 · clean file: 0 attacks |

---

## 7. Likely curveballs

- *"Why not fine-tune an LLM for classification?"* — offline constraint, cost, latency, non-reproducible probabilities; TF-IDF+LR hits 97.3% in 5 s on CPU and is fully inspectable.
- *"What if two uploads happen at once?"* — each gets its own id and folder; the model is read-only, so predictions are safe; the dev server serialises heavy work per analysis (documented limitation).
- *"How do you know 97.29% isn't overfitting?"* — stratified held-out split never touched in training; per-class metrics in `metrics.json`; corpus has 3% label noise and varied phrasings; and the honest caveat: synthetic data, so real-world accuracy is unproven.
- *"What's `ip_fail_ratio` and why does the model need it?"* — fraction of failed auth events from that IP in the window; brute force is defined by failure bursts, which pure text TF-IDF under-weights.
- *"Where does severity come from — the model?"* — no. The model gives category + confidence; severity is a deterministic documented rule layered on top (config table + one-step adjustments), so it's auditable.
- *"Delete my data — prove it."* — removes `tmp/<id>/` immediately via the API; sweep thread handles anything older than 60 min; tests cover the round trip including delete.
- *"Why does the clean file report zero attacks — is the model broken?"* — the opposite: below-threshold predictions are counted as Normal and shown as low-confidence notes; the dashboard states "No attacks were detected, so there is nothing to plot" rather than inventing findings.
