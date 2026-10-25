# CODEX MASTER IMPLEMENTATION BRIEF — CRYPTO-TRIPWIRE

You are acting as a principal Windows endpoint security engineer, DFIR researcher, detection engineer, research-methods reviewer, and rigorous software maintainer. Your assignment is to ENGINEER, IMPLEMENT, TEST, BENCHMARK, AND DOCUMENT the existing M.Tech minor project **Crypto-Tripwire: Entropy-Based Ransomware Detection for Automated Volatile Evidence Capture and Incident Response**. Do not stop at an architecture proposal, superficial UI, or pseudocode.

## 0. Non-negotiable context and deadlines

- Deployment target: **Windows guest with FLARE-VM inside VMware Workstation**. The code workspace may be on a different machine/OS; discover what can actually be run locally, and write Windows guest setup scripts and explicit verification commands for anything requiring the guest.
- Code review: **21 November 2026**; final review: **3 December 2026**. Prioritize a dependable, defensible demonstration ahead of optional features.
- Historical inputs (provided alongside this prompt): the original 12-page proposal, Zeroth Review PPT, First Review PPT, Second Review PPT, screenshots embedded in the presentations, and any existing project source repository. Inspect these FIRST. If any are absent, report exactly what is missing, then proceed from this brief rather than pretending to have inspected them.
- Official project title and four-phase semantics are frozen after three reviews. DO NOT replace the project with a different product, invent a new thesis, or make LLM/AI the core technology.
- Current declared status: Phase 1 entropy/watchdog prototype and Phase 2 psutil process/network JSON/SHA-256 collection were demonstrated with a benign Python file-activity simulation. Phase 3 is not reliably finished; Phase 4 has not begun. Treat slides as historical claims, not proof of implementation. Audit source code and rerun tests before assigning any feature a status.
- The current `.10` or other locked-looking files were generated in a self-made test; do not present them as evidence of real-world malware resistance.
- Do not delete existing working components. Preserve a legacy baseline to compare with your improved implementation. Use a compatibility adapter or modular refactor if necessary.

## 1. Scientific objective — unify the work

Establish **one experimentally falsifiable primary contribution**:

> A provenance-aware, latency-measured, ransomware-behavior-triggered Windows DFIR pipeline that automatically preserves endpoint evidence and reconstructs a traceable incident timeline before key volatile information disappears.

Keep the existing four phases:
1. **Detection:** entropy-centered behavioral file monitoring with calibrated contextual signals.
2. **Evidence capture:** automated collection of running-process and network metadata, Windows event records, hashes and, only if feasibly demonstrated, optional RAM acquisition.
3. **Timeline:** evidence-grounded reconstruction with provenance and calibrated attribution confidence.
4. **Report:** reproducible, automatically compiled incident report and evidence manifest.

Frame this as an experimentally evaluated *systems integration and measurement* contribution, not proof that no such system exists anywhere. Verify comparisons with prior art; do not assert global first-of-its-kind novelty without a defensible systematic review. Do not claim malware prevention, guaranteed pre-encryption blocking, decryption, full memory forensics, or a legally complete chain of custody unless actually implemented and demonstrated.

Primary research question: **Compared with an entropy-only trigger and a manually initiated metadata-capture baseline, does an integrated, event-correlated pipeline reduce trigger-to-evidence latency and improve incident reconstruction while maintaining an acceptable false-alert burden?**

Pre-register measurable hypotheses and explicitly state their null hypotheses. Defend why each feature exists, what evidence feeds it, what problem it fixes, and the measurable consequence of its removal.

## 2. Mandatory initial source/repo audit (perform before changes)

Inspect the documents, screenshots, repository, package versions, execution environment, tests, configs, and logs. Produce:
- `docs/00_source_alignment_matrix.md`: historical promise -> existing implementation -> measurable evidence -> proposed enhancement -> review risk -> status.
- `docs/01_gap_and_risk_audit.md`: component inventory, test failures, dependencies, permissions, Windows compatibility, security issues, unknowns.
- An explicit reconciliation of Second Review entropy threshold **7.2 bits/byte** and the conflicting **10+ vs 20 files / 5 seconds** trigger references. Establish one canonical versioned default from calibration, keeping previous thresholds as selectable baselines.
- Note that `psutil` process/network snapshots are **OS metadata, not a physical memory image**. Do not rename the metadata collection “RAM capture.”
- Note that `watchdog` file-change timestamps and contemporaneous process snapshots alone do **not prove which PID wrote a file**. Where event sources do not support causal attribution, label candidates/unknowns rather than invent evidence.
- Surface other inconsistencies between proposal, decks, and code rather than quietly rewriting historical facts.

Return a brief engineering action plan, then ACT ON IT. Avoid repeatedly requesting confirmation for ordinary implementation choices. Ask only about blockers that truly cannot be addressed by reasonable defaults.

## 3. Architecture to build

Maintain a modular and testable, local-first pipeline. Suggested package layout (adjust to the actual repo rather than forcing it):

```
crypto_tripwire/
  config.py
  domain/schemas.py
  telemetry/{watchdog_adapter,sysmon_adapter,psutil_adapter,etw_adapter}.py
  detection/{entropy,features,windowing,scoring,baseline}.py
  capture/{orchestrator,processes,network,eventlogs,manifest}.py
  timeline/{normalize,correlate,confidence}.py
  reporting/{html_report,docx_report,templates}.py
  metrics/{episodes,benchmark,stats,plots}.py
  cli.py
configs/    fixtures/    tests/    scripts/    docs/    results/
```

Required design properties:
- A documented versioned event schema (UTC time; monotonic time for same-host elapsed measurements; source; host; PID; process GUID if present; file path; operation; sequence/event record ID; provenance; confidence; schema version).
- Non-blocking detection and evidence capture: bounded queues, debouncing, explicit overflow/drop counters, retries, deduplication, cancellation, orderly shutdown, file locking handling, atomic writes, error logging and graceful degradation.
- The evidence collection must not itself recursively trigger false alarms: exclude output paths, with unit tests.
- No optional dependency may silently disable the full pipeline. Diagnostics must expose degraded mode and precisely which information is missing.
- Configurable **scoped test directory**; avoid scanning entire system or recursively touching drives by default.
- Risk-aware use of administrator privileges: report requirements, prefer least privilege for nonprivileged portions, never suppress alerts/prompts or disable endpoint protection merely to make a demo work.
- File hashing and integrity checks, including a verifier independent from the report generator; recording hashes does not alone imply tamper-proof custody on a compromised endpoint.
- Preserve the historical entropy-only implementation as a selectable benchmark (`baseline_entropy`) and the improved detector as `fusion` or similar.

### Phase 1 — measurement-driven detection

Keep Shannon byte entropy as the **central** feature. Implement/test:
- Streaming or bounded-byte entropy sampling that handles file-size effects, locked files, renames, burst writes, partially encrypted files and zero-byte files without pathological memory or CPU use.
- Configurable time windows and per-event deduplication.
- Where a known benign initial file state exists, compare entropy before/after; label entropy deltas unavailable when no baseline exists.
- Additional explainable behavioral signals: number of changed distinct files per window, rate, unusual rename/extension patterns, document-like targets, concentration across directories, optional evidenced process lineage, and explicit exclusion/handling of evidence-output paths. No one weak signal alone should yield unsupported claims.
- Carefully calibrate thresholds using held-out benign workloads rather than selecting one because it detects a single simulator.
- Output a structured reason for each alert: feature values, thresholds, evidence IDs, start/end of window, trigger time, and false-positive caveats.
- Handle benign high-entropy bursts (archives, copying compressed media, backups, installation/update workloads, many small files, legitimate encryption software) as negative tests.

### Phase 2 — pre-trigger context and immediate evidence

Keep existing psutil capture for process trees (PID, PPID, image, command line if permission permits, executable hash if feasible, process start/end where available), network sockets, permissions errors, and SHA-256 manifests.

Add **Sysmon-backed Windows event provenance** where feasible. Consult official Microsoft documentation and use appropriate IDs such as: 1 (process creation), 3 (network connection if enabled), 5 (process termination), 11 (file creation/overwrite), 22 (DNS), and selective 23/26 (file deletion), with GUID/record-ID-based correlations. Avoid high-volume defaults and state precisely what a chosen event does and does not observe. **Sysmon is not a complete log of all in-place file writes**; never treat it as such. A low-overhead Windows ETW file-I/O adapter can be an optional, separately verified enhancement if feasible, not a reason to stall the working product. Use a well-documented fallback when Sysmon or ETW is unavailable.

Maintain a bounded, non-destructive **pre-trigger telemetry buffer** or event-log query window: a process that terminates before the alert must still be reconstructable if it generated earlier events. On trigger, prioritize quick snapshots and event export; record timing of every collection stage. Use an evidence directory outside monitored fixtures, with a session ID, UTC manifest, collector/config versions, hash table, capture errors, Sysmon event IDs/record IDs and input-origin descriptions. Optionally export relevant `.evtx` or faithful XML/JSON event content where permissions support it.

Full physical RAM imaging with WinPmem/Volatility 3 was previously described as **future or major-project work**, not a guaranteed existing feature. If added, it MUST be opt-in, resource-checked, clearly isolated from the critical low-latency path, and marked as a separately validated extension. Never fake a memory image with a JSON process list.

### Phase 3 — trustworthy timeline and process linkage

Build this phase fully, not as a sorted list of snapshot entries:
- Normalize watchdog records, Sysmon event logs, psutil snapshots and optional ETW data into a single provenance-preserving event schema.
- Correlate by stable process GUID when present, PID plus lifetime as an alternative, Windows record IDs, path and meaningful time windows; do not join PIDs blindly across process restarts.
- Maintain explicit labels: `directly_observed`, `corroborated`, `temporal_association_only`, `unattributed`, each with machine-readable source references. Define these operationally in documentation.
- Resolve clock differences and timestamp precision; preserve original and normalized times, ordering ambiguity, duplicates, source gaps and process exit before capture.
- Generate a chronological timeline, a process-parent tree, alert-to-capture sequence and readable explanations for any correlation.
- Map validated observed behaviors cautiously to MITRE ATT&CK (notably T1486). Do not assign techniques unsupported by logged evidence.
- Include ground-truth comparison tests: event recall, ordering agreement and attribution precision/recall where labels truly exist.

### Phase 4 — automatically generated report

Generate an accurate, locally renderable **HTML report** and a practical DOCX or PDF export when supported. The incident report must contain: case/session identifiers; host/lab information; executive synopsis; precisely worded determination (suspected ransomware-like activity, not proof of a malware family); source coverage and gaps; trigger evidence; timeline; process/network metadata; artifact manifest with SHA-256 hashes; integrity verification result; capture duration; concise ATT&CK mapping with sources; investigative leads; caveats and next steps. Show uncertain correlations explicitly. Support JSON export and reproducible deterministic templates. Never involve a remote LLM or claim AI analysis as current scope.

## 4. Realism and containment — mandatory safety and evidentiary honesty

The faculty's criticism is that self-written Python scripts and `.10` files do not show resilience to **compiled real-world ransomware behavior**. Build a **three-tier validation design**, label tiers separately and NEVER conflate them:

**Tier A: safe live compiled behavioral workload.** Implement or integrate a benign, compiled Windows executable that performs representative *non-malicious* high-rate file operations only within an automatically created disposable fixture directory. Simulate high-entropy byte writes, extension changes, bursty file creation, varied file sizes, process spawn and ordinary file I/O. It must have an enforced path allowlist, a strict item/size/time limit, a visible safety check, no destructive encryption of existing user files, no network propagation, no persistence, no evasion, no disabling protections, and a hard stop. Ensure it is not a ransomware implementation. Include negative control executables where appropriate. Publish the source and binary hashes of this benign workload; do not label it real ransomware.

**Tier B: genuine malware-derived telemetry replay (required).** Support import and event-timestamp-faithful replay of independently documented Windows telemetry (e.g., Sysmon EVTX/JSON/ETW exports) captured in prior **genuine ransomware analyses**. Obtain datasets only from legally available sources; keep origin URLs, publication dates, licenses, hashes, family labels (if independently verified), instrumentation, available ground truth, and important blind spots. Build a source-to-schema adapter and reproducible replay harness. Keep replayed outcomes clearly labeled `offline telemetry replay`, never `live malware execution`. Do not invent dataset entries or results. If suitable verified public telemetry cannot be obtained, implement the ingestion and explicitly mark real-malware evaluation `NOT YET VALIDATED`, while reporting what evidence is still required.

**Tier C: institutionally approved live-malware laboratory evidence (optional and only under qualified supervision).** The project should be compatible with ingestion of evidence captured by a legitimate institution-operated, isolated malware-analysis lab. Do **not** download, distribute, execute, detonate, or automate real ransomware; do not write code or instructions to do so. Do not assume FLARE-VM or a VMware snapshot alone ensures safe containment. Real-sample analysis would require faculty/institution authorization, documented containment and independent expert operators. Treat MalwareBazaar as a **source of sample metadata, hashes and attribution context**, not a command to execute samples. Build safe evidence import and manifest support so professionally collected real-sample logs can be analyzed by Crypto-Tripwire without operationalizing malware here.

Provide a threat-to-observable matrix based on documented ransomware behaviors: bulk modifications, overwrite/rename, fast process exit, partial encryption, ransom-note-style artifacts, benign entropy lookalikes, and sensor blind spots. Explicitly state that a system which produces a fast report is not thereby proven to **stop encryption**. Any optional containment action must default OFF, require unambiguous attribution and separate authorization, and never be presented as tested unless truly measured.

## 5. Publication-grade quantitative methodology

Write `docs/experiment_protocol.md` BEFORE tuning to final performance. Predefine test episodes and controls, workload size, run count, hardware/VM specs, pre-test snapshots, versions, ground-truth annotation, measurement clocks, thresholds, split strategy and failure definitions. Do not fabricate values or post-hoc tune on the final test set.

Required comparisons:
- **B0:** historical entropy-only detector and historical evidence behavior.
- **B1:** calibrated entropy + burst threshold only.
- **B2:** improved entropy-centered multi-signal detector and triggered metadata/event capture.
- **B3:** B2 with provenance-aware timeline/report, to measure evidence usefulness separately from detector accuracy.
- Where legitimately feasible, measure a controlled **manual investigator capture** baseline rather than estimating hypothetical manual response times.

Workloads: benign documents and common compressed formats, mass benign copy/archive/backup/update operations, scoped compiled high-rate workload, varying file sizes and partial changes, and appropriately labelled genuine-malware-derived replay. Document domain shift from replay to real-time live behavior.

Required metrics, with unambiguous numerators/denominators and raw per-run records:
1. Episode-level TP, FP, TN, FN, confusion matrix, precision, recall/TPR, specificity, FPR and F1; distinguish **false alerts per hour** from episode-level FPR.
2. Detection delay from first ground-truth suspicious operation, plus false alarms during sustained benign workloads.
3. Trigger-to-first-artifact delay, trigger-to-snapshot-complete delay, and trigger-to-final-report delay; median, p95, ranges and sample counts.
4. Pre-trigger process/event recall, evidence capture completeness, hash-verification success, missing-field and collector-failure rates.
5. Timeline event recall, order correctness and PID/process-guid attribution precision *only where trustworthy ground truth exists*.
6. CPU, RAM, disk I/O and dropped-event overhead with detector enabled versus disabled under comparable workloads.
7. Files changed before detection (for safe fixture runs only), normalized by workload; do not imply protected files without separate prevention logic.
8. Parameter sensitivity and ablation tests (entropy alone; burst signal; rename/extension; process provenance). Account for potential correlation and false-positive tradeoffs.

Provide plots from real measured raw CSV/JSON: ROC or precision-recall if scores support it; distribution/box plots of latencies, false-alert rates, resource overhead, confidence intervals, ablation table and a comparison matrix. Use multiple independent trials (target >=10 per repeatable workload where practical; report actual N). Use suitable 95% intervals (e.g., bootstrap at episode/trial level) without pseudoreplication. Never invent a study result or present illustrative plots as experimental proof. Validate metric formulas with synthetic **metric unit tests** whose numbers are clearly fixtures, not findings.

## 6. Deliverable repository and quality bar

Build runnable, documented code, not a pitch deck masquerading as implementation. Expected outputs:

- Usable Python project with pinned/locked dependencies, clear CLI: `doctor`, `monitor`, `capture`, `analyze`, `report`, `verify`, `benchmark` (change names only when justified).
- Windows guest bootstrap and doctor scripts that check privileges, Python, Sysmon status/schema/config, event channel access, watchdog path, clock/disk availability, psutil network/process access, and isolation assumptions. Prefer documented installation from official project pages. No hidden downloads or disabling protective controls.
- Versioned sample configuration with all paths and thresholds documented.
- Recorded event adapters and unit/integration tests, replay fixtures, safe compiled workload source and build instructions, and test corpus manifest.
- Robust machine-readable artifacts in `results/<case-id>/`: `events.jsonl`, `alert.json`, `capture.json`, `timeline.json`, `manifest.json`, `verification.json`, report files, benchmark CSV/JSON and plots (where genuinely generated).
- Automated test suite (`pytest` or equivalent), lint/static checks as feasible, honest coverage notes, and CI config for platform-independent tests; isolate Windows integration tests via markers.
- Security review of untrusted event fields and file paths, safe output escaping, path traversal defense, large-file defense, exception handling, no arbitrary shell execution from parsed telemetry.
- A 5–8 minute **code review demo** with exact commands, expected real outputs and fallbacks; a separate final-review demonstration script; reproducibility checklist and common failure recovery notes.
- Architecture/dataflow diagram, source-provenance example, quantitative evaluation tables from actual data, explicit threats to validity, limitations and future-work section.
- `paper/paper_outline.md` and a publication-style draft (abstract, research questions, contribution, related work, reproducible method, experimental setup, real results only, validity, conclusion); verified citations/DOIs; venue selection as suggestions only. Do not promise acceptance or claim institutional endorsement.
- `docs/panel_defense.md`: rigorous answers to “What is new?”, “Why entropy?”, “What does your system detect?”, “Which PID modified that file?”, “Was actual ransomware executed?”, “Does it prevent damage?”, “Is SHA-256 a chain of custody?”, “What is the real contribution?”, and “How were your metrics measured?”.

## 7. Delivery schedule (2026) and acceptance gates

**By 1 Nov:** repo/source audit, architecture, safe lab readiness, clean legacy baseline, automated unit tests, reconciled threshold configuration.

**By 8 Nov:** improved detector, Windows event source adapter, evidence collection with event retention, reproducible alert and manifest; benchmark harness begins.

**By 15 Nov:** Phase 3 and Phase 4 both run end-to-end, safe compiled fixture tests, event replay loader, independent verification, automated report.

**By 20 Nov:** freeze a reliable code-review candidate: working VM demo, regression tests, measured preliminary plots, documented limits, failure fallback. The 21 Nov code review must show code/data rather than aspirational slides.

**22 Nov–2 Dec:** wider controlled experiment matrix, uncertainty/CI analysis, traceable real-derived replay where legitimately sourced, ablation, polished figures and paper draft, final-review rehearsals. Final review **3 Dec 2026**.

Acceptance is achieved only if:
- The existing approved four phases demonstrably execute without manual handoffs during one scoped safe-live test.
- The improved pipeline has a reproducible, measured baseline comparison and episode-level metrics; no simulated numbers are passed off as measured.
- An independent verifier validates artifact hashes; error and missing-source conditions are visible.
- The timeline distinguishes direct observation from inference and can support at least one process-correlated Windows telemetry example.
- The report correctly presents incident details, method limitations and metric denominators.
- The system runs in the FLARE-VM guest (or, until guest validation is possible, is clearly labelled not guest-validated with exact guest verification steps).
- No claim of detection against live genuine ransomware is made without verified live genuine-ransomware execution evidence gathered under appropriate institutional supervision.

## 8. Work style and response protocol for Codex

1. First response: show the repo audit, prioritized architecture, what can be immediately executed here, key missing capabilities, and the *first concrete edits*. Then **perform** edits; do not merely offer a future implementation.
2. Make incremental patches and keep the legacy baseline executable. After each coherent module, run tests where supported, paste genuine commands and concise outputs, and fix failures. For Windows-only functionality not testable in the current runtime, implement and unit-test parser/logic with fixture data and explicitly provide guest verification instructions.
3. Use official Microsoft Sysmon/ETW documentation, MITRE ATT&CK T1486 and primary research literature for any technical facts; distinguish sources from assumptions. Do not blindly adopt incorrect API/event-ID claims from third-party writeups.
4. Design for **scientific honesty**: mark `verified`, `partially_verified`, `not_tested`, `not_available`, and never invent metrics, screenshots, citations, hardware, datasets or success statuses.
5. Prefer a reliable working endpoint collector and provenance-based Phase 3 over unnecessary deep learning, LLMs, cloud services, custom kernel drivers or cosmetics. If time is constrained, ship the smallest complete experimental result, then enhancements.
6. Keep all code and telemetry collection defensive. Do not provide ransomware payload development, credential collection, propagation, persistence, sandbox evasion, real-malware deployment, or a launcher for samples from MalwareBazaar. Build integrations for **defensive telemetry**, safe workloads and externally obtained research traces only.
7. Maintain `PROGRESS.md` with completed features, tests/results, blockers, next actions and deadline risk. End each implementation response with changed files, real verification status, how to run the next guest check, and what scientific claim the new evidence supports.

**BEGIN NOW:** inventory actual files and repository. Preserve the official project trajectory, execute the first safe implementation steps, and work toward a testable four-phase prototype with an honest comparative research result by the stated dates.
