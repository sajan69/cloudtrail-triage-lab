# Evaluation and local measurements

## Reserved synthetic cases

Fixed detection rules were evaluated on five reserved seeds (101, 203, 307, 409, 503), producing 660 synthetic events across 65 scenario cases. Development seed 42 was separate. No thresholds were changed using these results. Labels never enter the detection database.

Each case is scored once per rule. Any finding evidence intersecting a case makes it predicted-positive for that rule; a finding crossing cases marks each intersected case and is counted separately in the detailed report. The current fixtures produced no cross-case findings.

| Rule | TP | FP | FN | TN | Precision | Recall | False-positive rate |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| CT001 | 5 | 5 | 0 | 55 | 50% | 100% | 8.33% |
| CT002 | 5 | 5 | 0 | 55 | 50% | 100% | 8.33% |
| CT003 | 5 | 0 | 0 | 60 | 100% | 100% | 0.00% |

CT001 flags authorized permission audits and CT002 flags approved emergency sign-ins in these fixtures. Those are deliberately retained false positives. CT003 matched its positive templates without false positives in this small suite; this is not evidence of perfect detection in real environments. Undefined ratios are represented as null in JSON.

**Shared-template limitation:** both development and reserved seeds use the same hand-authored scenario templates. Seed, IDs, times and ordering vary, but this does not measure out-of-template or real-world generalization. Case prevalence, background activity and labels are artificial. These are case-level results, not per-event or production accuracy.

Reproduce with `triage evaluate`. The full [recorded report](reports/evaluation.json) includes per-seed case predictions and software versions.

## Measured local workload

The benchmark used 1,032 synthetic events (582,865 input bytes), seed 42, and 3 repeats. Each import used a new database; detection and a filtered timeline query followed it. Timings include parsing/validation, database connections and SQL work. Repeated inputs can benefit from OS caches.

| Operation | Median wall time |
| --- | ---: |
| Validate and import | 1,892.724 ms |
| Run three detection rules | 31.077 ms |
| Query Bedrock event timeline | 14.266 ms |

Environment: Python 3.12.14, DuckDB 1.5.6, package 0.2.0, Linux x86_64, 9 reported logical CPUs. The connection limits DuckDB to two threads and 256 MiB; the shared host's full resources were not dedicated to this workload.

These timings are observations from one environment, not a latency SLA, capacity estimate, AWS measurement or speedup over another implementation. Storage, cache state and concurrent load matter. No production throughput claim is made.

Reproduce with `triage benchmark --background 1000 --repeats 3`. See [all samples and method](reports/benchmark.json).

## Integrated checks

`triage demo` uses temporary synthetic data to verify import, duplicate handling, five expected development findings, filtered timelines, selected finding evidence, JSON/CSV export, token denial (403) and authorized local HTTP access (200). It removes its temporary data and makes no AWS calls. See [recorded demo output](reports/demo.json).

Python CI runs the full suite on 3.11, 3.12 and 3.13. A separate browser check installs the built package and verifies controls, downloads, responsive layout and an inert HTML payload. Its screenshot is uploaded as a CI artifact.

For local browser checks, install Node.js and run `npm ci --ignore-scripts --prefix tests/browser`, then `node tests/browser/node_modules/playwright/cli.js install chromium`, then `npm test --prefix tests/browser` using a Python environment with this package installed. `TRIAGE_PYTHON` can select that environment; `CHROMIUM_EXECUTABLE` can select an already installed browser. These development dependencies are not needed to use the application.
