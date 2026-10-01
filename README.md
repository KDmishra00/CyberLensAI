# CyberLens AI

A standalone, offline desktop web app for analysing historical cybersecurity
data. You give it a log file or dataset; it validates the file, shows you a
preview, cleans the data, runs a pre-trained classifier over it, assigns a
severity to every detection, suggests mitigations, and writes it all up as a
PDF incident report. Everything runs on your machine. It never touches a live
network and never executes anything found inside an uploaded file.

Built as a university lab project (Manipal University Jaipur) by
Kuldeep Mishra and Samay Shakya.

## Screenshots

Add screenshots here once taken: home, upload, preview, dashboard (light and
dark), report view, and one page of the PDF.

## Run it

Three commands from the project root:

```bash
pip install -r requirements.txt
python train_model.py
python app.py
```

Then open http://127.0.0.1:5001

(Port 5001, not 5000, because macOS AirPlay Receiver occupies 5000. Set
`CYBERLENS_PORT` to override.)

## How to use it

1. **Upload** - drop a `.csv`, `.xlsx` or `.log` file (max 20 MB) onto the
   upload page and press Upload. The file is validated before anything reads
   it: extension, size, decodable text, and for Excel a real zip structure
   with no macros.
2. **Check** - the preview page shows the first 20 rows, how each column was
   read, missing-value counts, and the parse success rate for log files.
3. **Analyse** - press "Run analysis". Real pipeline stages stream into the
   status line while it works.
4. **Read the results** - the dashboard shows totals, category and severity
   breakdowns, a timeline, top source IPs, a filterable detections table, and
   mitigations per detected category. "Explore the data in 2-D" opens a PCA
   scatter plot coloured by predicted category.
5. **Report** - "View report" shows the same story as a printable page;
   "Download PDF" saves it. "Delete my data" removes everything immediately.

Sample files for trying it out live in `data/samples/`:

| File | What it is |
|---|---|
| `auth_bruteforce.log` | 4,850-line syslog/auth log with three brute-force bursts |
| `web_access.log` | 9,577-line Apache combined log with SQL injection, a port scan and a flood |
| `mixed_incidents.csv` | Tabular dataset with deliberately non-canonical column names, all six attack types, and a label column |
| `network_flows.xlsx` | Excel flow table (first sheet) with scan and DoS traffic |
| `clean_normal.csv` | Normal traffic only - shows the honest nothing-found state |
| `broken.csv` | Malformed rows, blank lines, latin-1 characters, duplicates |

`not_allowed.pdf` and a >20 MB `too_big.csv` are generated on demand by the
tests and deliberately not committed.

## Project structure

```
app.py            Flask entry point: pages, JSON API, background pipeline, sweep
config.py         Every tunable in one place (limits, thresholds, severity table)
train_model.py    Builds and saves the model (run once)
make_samples.py   Regenerates the sample files in data/samples/
corpus.py         Seeded synthetic event corpus (shared by trainer and samples)
core/
  upload.py       Validation, safe storage, macro/zip-bomb guards
  parser.py       CSV/XLSX fuzzy column mapping + four log-format extractors
  preprocess.py   Dedupe, timestamp normalisation, missing values, derived features
  analyzer.py     Model loading, batch prediction, anomaly/low-confidence flags
  security.py     Severity rule + mitigation lookup
  stats.py        Totals, breakdowns, top lists, auto-bucketed timeline
  report.py       Summary text + ReportLab PDF
data/mitigations.json   Mitigation steps and MITRE ATT&CK refs per category
models/           cyberlens_model.joblib + metrics.json (created by training)
templates/        Jinja templates (base, index, upload, preview, dashboard, report, about, error)
static/           One stylesheet, three small JS files, vendored Chart.js
tests/            pytest suite
tmp/              Uploads and working files, swept after 60 minutes (git-ignored)
```

## How the model was built

`train_model.py` generates ~20k labelled events from `corpus.py` - varied
phrasings, IPs, usernames, timestamps and ports, with per-IP behavioural
patterns (bursts of failures, port sweeps, beaconing, floods) and about 3%
label noise. The corpus is deliberately written to match what the log parser
extracts at inference time: the source IP is whatever appears in the event
text, most system events have no username, and so on. That alignment matters
more than the classifier choice.

The saved pipeline is a sklearn `ColumnTransformer`: TF-IDF over the cleaned
event text (word 1-2 grams plus char 3-5 grams) stacked with 12 scaled
numeric features (bytes, duration, port, per-IP event counts, ±30 s rate,
distinct ports/users, failure ratio, event length, and SQL / privilege /
malware token indicators), fed to a LogisticRegression. Logistic regression
was chosen over a random forest because it trains in seconds on the sparse
stacked features, and gives smooth probabilities that the severity rule and
the 0.55 anomaly threshold rely on.

On a stratified held-out split it scores **97.2% accuracy**; the exact
per-class precision/recall/F1 are in `models/metrics.json`, printed by
training, and shown honestly on the dashboard. This is performance on
synthetic data and says nothing about real-world accuracy.

### Limits of the model

- It knows exactly seven categories: Normal plus the six attacks on the home
  page. Anything else (SSH tunnelling, DNS exfiltration, insider misuse,
  phishing emails...) is out of scope and will mostly be called Normal.
- It was trained on synthetic logs. Real logs have vendor-specific formats,
  noise, and attack patterns this corpus does not model.
- Attack calls with confidence below 0.55 are counted as Normal and reported
  separately as low-confidence; the tool would rather under-report than
  inflate an attack count.

### Swapping in a real dataset

To retrain on something like CIC-IDS or UNSW-NB15: export the rows with a
message/text column plus bytes/duration/port if available, put the ground
truth in a column named `label`, then either feed the file through
`core.parser.parse_file` (so features match the app) or adapt
`corpus.corpus_blocks` to return your rows in the same dict shape. Run
`python train_model.py` again - it overwrites `models/cyberlens_model.joblib`
and `metrics.json` and prints the new report. The app picks the new model up
on restart. Keep the feature list in `config.MODEL_NUMERIC_FEATURES` in sync
with what you train on.

## Severity rule

How a detection's severity is decided (also shown on every report):

| Category | Base |
|---|---|
| Malware Activity | Critical |
| SQL Injection | High |
| Privilege Escalation | High |
| DoS Indicators | High |
| Brute Force | Medium |
| Port Scan | Low |

Then: **+1 level** if model confidence is at least 0.90 or the same source IP
produced at least 20 attack events; **-1 level** if confidence is below 0.65.
Clamped to Low / Medium / High / Critical - exactly those four, nothing else.

## Decisions made where the spec was ambiguous

- **Port 5001** - 5000 is taken by AirPlay on modern macOS; configurable via
  `CYBERLENS_PORT`.
- **ReportLab for PDFs**, with a hand-drawn ReportLab graphics line chart for
  the timeline rather than adding matplotlib as a dependency.
- **Chart.js 4.4.9 vendored** into `static/vendor/` during setup; the app
  makes no network requests at runtime.
- **In-memory analysis state** (a dict keyed by a random 32-hex id) plus the
  `tmp/<id>/` folder. Restarting the server forgets running analyses; the
  uploaded files remain until swept or deleted. A database was explicitly
  out of scope.
- **Log parse success rate** is defined as: non-empty lines where an event
  was extracted *and* (a timestamp or an IP was found). Both sample log files
  measure 100%.
- **Ephemeral client ports (>= 49152) are excluded** from the "top targeted
  ports" list, otherwise SSH traffic's random source ports dominate it.
- **"Analyse" is only offered after a successful upload and parse.** The
  preview renders from the parsed data, so a file that cannot be parsed never
  reaches an Analyse button.
- **Fuzzy column mapping is intentionally conservative**: first matching
  alias wins and each original column maps to at most one canonical field.
  Unmapped numeric columns ride along as display extras (capped at 20) but
  are not model features.
- **pandas 3 compatibility**: timestamps are parsed with explicit routes for
  no-year syslog dates (assume the current year) and Apache `%d/%b/%Y:%H:%M:%S %z`
  strings, because pandas' `format="mixed"` silently mis-parses both.
- The web log sample ships **two Privilege Escalation events that are
  actually a mislabelled corner of the synthetic generator**; we left them in
  because a 100%-clean confusion matrix would look dishonest.

## Tests

```bash
python -m pytest tests/ -v
```

23 tests cover: extension/content rejection, macro-workbook rejection,
oversize rejection, each log format's field extraction, timestamp
normalisation (including epoch and no-year syslog), duplicate removal, fuzzy
column mapping, model loading, prediction shape and value ranges, severity
staying within the four allowed values, stats sanity (attacks + normal =
total, category and severity sums), the clean file's empty state, PDF
validity, and a full upload → analyse → results → detections → PDF → delete
round trip through Flask's test client. Two tests print the measured log
parse success rate; both measure 100% (target: >= 95%).

## Security and privacy behaviour

- Uploads are treated strictly as data. Nothing is executed; the original
  file is never modified; nothing is served back to the browser.
- Macro-enabled workbooks (`.xlsm` content, `vbaProject.bin`) are refused,
  as are files that decompress beyond 200 MB or exceed 500k rows.
- CSP allows only self-hosted scripts/styles; all user-derived text is
  rendered with `textContent` (never `innerHTML`) and Jinja autoescape stays
  on. Result pages send `Cache-Control: no-store`; every response carries
  `X-Content-Type-Options: nosniff` and a restrictive `Referrer-Policy`.
- Exported table cells starting with `=`, `+`, `-` or `@` are prefixed with a
  quote to defuse spreadsheet formula injection.
- Analysis folders are deleted on request ("Delete my data") and swept
  automatically after 60 minutes.

## Known limitations

- Single user, single request at a time per analysis; the Flask dev server,
  not a production WSGI stack.
- Analyses live in memory: restarting the app discards dashboards (files
  stay on disk until swept).
- The model is a demonstration trained on synthetic data - see above.
- Only English-language, IPv4-centric log formats are recognised.
- Timeline buckets are chosen automatically (minute/hour/day); sub-minute
  bursts within one bucket are not separable.
- XLSX parsing reads the first non-empty sheet only.
