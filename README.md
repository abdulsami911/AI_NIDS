# AI-NIDS

AI-NIDS turns a Wireshark capture into a list of network flows, assigns a category where the training data supports a prediction, and links each result back to its original frames. The Flask dashboard runs locally. The default is a validation-weighted ensemble of Random Forest, XGBoost and KNN. Each member can also run independently.

## Run the dashboard

From the project root, use the existing environment and saved models:

```bash
.venv/bin/python run_nids.py
```

Open [the dashboard](http://127.0.0.1:5000). Choose a `.pcap`, `.pcapng`, or compatible flow-feature `.csv` file under 30 MB and select **Analyze with every model**. The file is extracted once, then Random Forest, XGBoost, KNN and the weighted ensemble all analyze the same flows. Model tabs on the result page compare their categories, scores, alerts and SOC ordering. For a quick check, upload [ordinary-http.pcapng](datasets/pcap_samples/ordinary-http.pcapng). With the recorded ensemble release it yields 12 frames, one Normal flow (score .8919) and zero alerts.

To recreate the environment on another machine, install Wireshark/TShark, create a Python virtual environment, and run `python -m pip install -r requirements.txt pytest` inside it. This workspace was tested with Python 3.14.8 and TShark 4.6.9. The machine needs the dataset files for training and the saved pipeline plus its matching report for inference. Capture traffic manually in Wireshark, save it, and upload the file; the application has no live-capture feature.

**Clear one result** by opening the capture, expanding **Clear this result**, and confirming. **Clear all finished results** on Overview clears completed and failed analyses together. This removes their flow predictions, frame mappings and contributions to dashboard totals. Original uploads are retained under `storage/captures/`. Training artifacts, benchmarks and previously exported files are separate. You can upload your next file immediately.

## What a result means

| Dashboard term | Meaning |
|---|---|
| Frame | One record in the original capture. Frame numbers are specific to that file. |
| Flow | A conversation grouped by transport stream, interface, VLAN, endpoints and time window. A request and its reply can belong to one flow. |
| Assessed | The flow passed the model's coverage check and received a category. Both Normal and attack-category predictions count. |
| Unassessed | The flow was reconstructed, but its transport/service or combination of forward and reverse packet-count ranges had no real training examples. Its frames remain available to inspect. |
| Skipped frame | The extractor could not assign this frame to a supported TCP/UDP flow. ARP and ICMP are examples. |
| Predicted Normal | The model selected Normal. The score expresses support for that decision under the fitted model. Ground truth requires independent evidence. |
| Attack-category prediction | The model selected a category such as DoS, Exploits or Fuzzers. An **alert** appears when its unrounded category score exceeds the release's validation-derived alert threshold. |

The model classifies flows because the proposal datasets provide one label per connection record. Every packet shown inside an assessed flow inherits that flow category for investigation. It is not an independently classified packet.

### How Wireshark packets receive a category

A PCAP packet is not sent directly to a model as a row. UNSW-NB15 and NSL-KDD describe connections, while a Wireshark file contains individual frames. The application therefore performs the following conversion:

1. **TShark decodes frames.** It reads the original frame number, timestamp, interface, VLAN, IP addresses, transport protocol, TCP/UDP ports, stream identifier, application dissector and packet lengths. It does not use payload content as a model feature.
2. **Frames are grouped into bidirectional flows.** A flow represents the two directions of one TCP or UDP conversation within the configured timeout. A TCP opening or DNS response helps identify the responder; otherwise, the first observed sender becomes the forward side.
3. **The flow becomes one feature row.** The engine calculates `proto`, `dur`, `spkts`, `dpkts`, `sinpkt`, `dinpkt`, `is_sm_ips_ports`, `service`, `sbytes` and `dbytes`. These names and units match the selected UNSW-NB15 capture-feature contract as closely as the available packet evidence permits.
4. **Coverage is checked before inference.** The flow's protocol, service and directional packet-count ranges must have support in the real UNSW training rows. Unsupported combinations become **Unassessed** rather than being forced into an attack category.
5. **The ensemble predicts the flow.** Random Forest, XGBoost and KNN each produce probabilities for the ten UNSW categories. The ensemble averages matching class probabilities and chooses the strongest category, subject to the validation-derived Normal rule.
6. **The alert rule is applied.** A predicted attack category raises an alert only when its score is strictly above the model's saved threshold. A below-threshold attack-category prediction remains visible but is not promoted to an alert.
7. **The result is linked back to packets.** Every supported frame retains its `flow_id` and original Wireshark frame number. The interface displays the flow prediction beside its packets. This means “packet category” is shorthand for “the category of the flow containing this packet.”

For SOC use, every reconstructed flow now receives an ensemble triage score. If the flow passes coverage, the lead becomes an assessed category and may alert. If it fails coverage, the saved category remains **Unassessed**, but the queue displays a provisional ensemble lead such as “Normal at 63.8%” or “DoS at 45.0%.” This is a ranking aid only: outside-coverage leads cannot raise alerts and must not be counted as confirmed Normal or attack traffic. The investigation queue orders alerts first, assessed attack predictions second, coverage gaps by lead score third, and assessed Normal flows last.

### Accepted upload formats and multi-model comparison

Only these file types are accepted:

- `.pcap` and `.pcapng`: real Wireshark capture formats. TShark decodes frames, the engine builds flows, and the packet investigation page retains original frame numbers.
- `.csv`: pre-extracted flow rows containing all ten deployment inputs: `proto`, `dur`, `spkts`, `dpkts`, `sinpkt`, `dinpkt`, `is_sm_ips_ports`, `service`, `sbytes`, and `dbytes`. Protocol must be TCP or UDP; numeric values must be finite and nonnegative; packet counts and the indicator must be integers. Endpoint and time columns are optional. CSV rows do not contain original packets, so their frame count and packet-investigation table are empty.

Documents, executables, archives and arbitrary CSV schemas are rejected. Dataset label columns such as `attack_cat` are ignored during upload inference and are never supplied to the classifiers.

Every accepted upload runs all four saved inference choices. Results are stored together by `flow_id`, so selecting a model never changes the extracted evidence. The default view is the weighted ensemble; tabs expose Random Forest, XGBoost and KNN independently. A flow page also provides the same tabs, allowing the analyst to compare disagreement on exactly the same packets. CSV export applies to the currently selected model.

```text
PCAP/PCAPNG
  -> decoded Wireshark frames
  -> bidirectional TCP/UDP flows
  -> UNSW-compatible flow features
  -> training-coverage check
  -> RF, XGBoost and KNN probabilities
  -> probability average + Normal/alert policy
  -> flow category linked to original frame numbers
```

This distinction prevents a misleading claim: the model was not trained on raw packet bytes, screenshots, frame numbers or IP addresses. It was trained on labeled connection records and receives reconstructed flow measurements at inference time.

### UNSW-NB15 categories

| Category | Meaning in this project |
|---|---|
| Normal | Dataset traffic labeled as ordinary activity. |
| Analysis | Probing or analytical activity represented by the dataset's Analysis label. |
| Backdoor | Traffic associated with unauthorized backdoor behavior in the dataset. |
| DoS | Denial-of-service behavior intended to exhaust or disrupt a service. |
| Exploits | Attempts to use a software or protocol vulnerability. |
| Fuzzers | Malformed or unusual inputs generated to discover faults. |
| Generic | The dataset's Generic cryptographic attack family. |
| Reconnaissance | Scanning and information-gathering behavior. |
| Shellcode | Traffic associated with code intended to open or control a shell. |
| Worms | Self-propagating malware behavior represented by the dataset. |

These are learned dataset categories. Confirming an incident requires packet evidence, service impact, endpoint logs, or ground-truth experiment records.

On the capture page, click **Predicted Normal** or **Unassessed** to filter the table. Open **Investigate** to see model inputs and frame numbers. **Model analytics → Upload history** records the filename, actual model release, time, assessed flows, Normal predictions and alerts. Training a later release leaves the earlier run attributable to its original model.

## Project workflow

1. **Train offline.** Load the official UNSW-NB15 split files, separate the labels from predictors and compare Random Forest, XGBoost and KNN. The deployment study keeps TCP/UDP rows with inputs that TShark can measure. NSL-KDD gets its own independently fitted binary pipelines. PCAP files are never training inputs.
2. **Compare on validation data.** Identical seven-feature vectors stay together when splitting the UNSW training data. Compare a seven-feature baseline, an enriched feature set, and enriched sets with capped SMOTENC targets of 600, 1,200 and 2,400 rows per minority category. Choose by validation macro-F1, with lower false-positive rate breaking ties. The ensemble weights are then selected from grouped validation results.
3. **Freeze and evaluate.** Refit the selected configuration, store the real training coverage and decision cutoffs, then score the official test split. Save the pipeline, label encoder, feature order, model identity, and report with data and artifact hashes.
4. **Extract a new file.** For PCAP/PCAPNG, TShark reads observed timestamps, packet lengths, headers and frame numbers. The flow builder infers direction from a TCP opening or DNS response when available, falling back to the first observed sender. For CSV, the strict validator reads already extracted ten-feature flow rows. The default capture flow time limits are 60 seconds.
5. **Classify and investigate.** The dashboard verifies all four registered artifact hashes and schemas, checks each model's coverage, and runs Random Forest, XGBoost, KNN and the ensemble. SQLite stores every model result against the same flow and frame mapping. Tabs and selected-model CSV export expose their differences.

The active enriched models use protocol, duration, forward and reverse packet counts, forward and reverse mean interpacket times, same-address-and-port indicator, decoded service, and forward and reverse IP byte totals. Wireshark frame lengths include link-layer bytes, so the separately displayed wire-byte total can differ. [Feature definitions](docs/FEATURE_AND_ACCURACY_LIMITATIONS.md)

### Why the two datasets do not share one feature pipeline

UNSW-NB15 and NSL-KDD have different schemas, label vocabularies, collection methods and preprocessing requirements. The project does not rename unrelated columns or combine their rows.

| Property | UNSW-NB15 primary study | NSL-KDD independent benchmark |
|---|---|---|
| Purpose | Trains and tests the deployable Wireshark category models | Tests whether the same three algorithm families work on a second established dataset |
| Training input | Official UNSW training CSV | `KDDTrain+.txt` |
| Test input | Official UNSW testing CSV | `KDDTest+.txt` |
| Target | Normal plus nine attack categories | Binary Normal or Attack |
| Predictors | 42 for the offline benchmark; ten capture-compatible inputs for deployment | 41 NSL-KDD predictors with its own categorical encoding |
| Saved pipelines | `capture_*.joblib` and full-feature registry artifacts | `nsl_kdd_*.joblib` |
| Used for uploaded PCAP inference? | Yes, only the capture-compatible UNSW pipelines | No |

Each dataset is fitted and evaluated independently. An NSL-KDD model cannot accept the ten UNSW capture inputs, and its binary Attack output cannot supply an UNSW category. NSL-KDD performance is therefore reported as a separate generalization benchmark, not averaged with UNSW results and not used to vote on uploaded captures.

The full 42-feature UNSW benchmark also does not classify uploaded PCAPs. Features such as historical connection counts, original exporter state and loss statistics cannot be reproduced reliably from an isolated capture. Deployment uses only the separately trained capture-feature suite. This avoids silently filling unavailable columns with invented zeros.

### How false alarms were reduced

The project uses several controls rather than claiming that one accuracy number eliminates false positives:

- **Grouped validation:** duplicate seven-feature vectors stay in the same fit or validation partition, reducing leakage from nearly identical records.
- **More discriminative inputs:** decoded service and directional IP bytes separate flows that have similar duration and packet counts. On the grouped holdout, XGBoost macro-F1 improved from `.238` for the seven-feature baseline to `.627` with enriched inputs and `.667` after fit-only minority resampling.
- **Fit-only capped SMOTENC:** minority categories are oversampled only inside the fitting data. Targets of 600, 1,200 and 2,400 are compared rather than assuming maximum balancing is best. Validation and official test rows remain untouched. The selected targets are 600 for Random Forest, 1,200 for XGBoost and 600 for KNN.
- **Validation-weighted ensemble:** grouped validation selected weights of 50% Random Forest, 30% XGBoost and 20% KNN. Every model still votes, but the strongest validation contributor has more influence.
- **Normal runner-up rule:** if Normal is the second-highest class and is sufficiently close to the leading attack class, the prediction may be changed to Normal. Its margin is selected from labeled UNSW validation data while allowing no more than one percentage point of validation attack-recognition loss.
- **Alert threshold:** an attack-category prediction becomes an alert only above a threshold learned from Normal validation scores. Ties do not alert.
- **Coverage abstention:** unfamiliar protocol/service/count combinations are labeled Unassessed. This avoids confident-looking categories where the training data provides no basic support.
- **Separate external reporting:** USTC PCAPs never tune thresholds or models. False-positive candidates from the benign Gmail capture are reported instead of being fed back into training.

These controls reduce unnecessary alerts but do not guarantee a low rate on every network. For the new ensemble on the official UNSW test split, 12.14% of labeled Normal flows raised alerts and 85.92% of labeled attack flows raised alerts. The separately tested benign Gmail capture produced zero alerts among 143 assessed flows. Domain shift and unsupported services remain important limitations.

### Performance-improvement plan

Improvements should be accepted only when they raise rare-category performance and reduce false alarms on data that was not used for fitting. The recommended sequence is:

1. **Establish immutable evaluation sets.** Keep the official UNSW test split, NSL-KDD test split and external PCAP checks untouched. Add a separately labeled local capture set containing known Normal applications and controlled, authorized security-test traffic. Do not use `firsttime.pcapng` as attack training data because it is ordinary traffic without flow labels.
2. **Validate extractor parity.** Export the same controlled traffic through the UNSW-compatible Argus/Bro feature process and this TShark engine, then compare flow boundaries, direction, byte accounting, service, duration and interpacket intervals. Fixing measurement mismatch is likely more valuable than blindly adding model complexity.
3. **Improve safe capture features.** Evaluate reproducible features such as TCP flag counts, handshake completion, packet-size statistics, directional rates and bounded recent-flow statistics only after documenting exact extraction rules. Never add a feature to training unless the identical quantity is available during PCAP inference.
4. **Tune each retained model.** Use grouped, stratified cross-validation on the UNSW training split to tune tree depth, number of trees, learning rate, KNN neighbor count and distance weighting. Optimize macro-F1 together with Normal false-positive rate instead of accuracy alone.
5. **Tune the ensemble weights.** Equal averaging is a reproducible baseline, but validation may support weights such as stronger XGBoost/Random Forest influence and lower KNN influence. Select weights and class-specific thresholds using training-fold predictions only, then evaluate once on the official test set.
6. **Improve rare categories carefully.** Compare class weights, capped SMOTENC targets and one-versus-rest calibration for Analysis, Backdoor, DoS, Shellcode and Worms. Report per-class support, precision and recall so oversampling is not mistaken for new independent evidence.
7. **Calibrate and abstain.** Compare probability calibration and a minimum confidence/margin rule. A model should return Unassessed or Needs review when members strongly disagree or confidence is insufficient, instead of always forcing a category.
8. **Measure domain shift.** Track performance by service, protocol, flow size and capture source. A release should be promoted only if it improves macro-F1 or rare-class recall without exceeding an agreed Normal-alert budget on both held-out UNSW data and labeled local Normal traffic.
9. **Keep experiments reproducible.** Save the seed, data hashes, feature schema, fold definitions, parameters, thresholds, confusion matrix and artifact hash for every candidate. Never replace the active release merely because it performs better on one uploaded PCAP.

The completed improvement experiment raised ensemble macro-F1 from `.540` to `.562`, reduced the official-test Normal alert rate from `12.64%` to `12.14%`, and increased attack alert recall from `83.79%` to `85.92%`. The next experiment should focus on extractor parity and independently labeled local Normal traffic rather than tuning against `firsttime.pcapng`.

## Models, datasets and results

| Algorithm | How it makes a decision |
|---|---|
| Random Forest | Fits many randomized decision trees and combines their class estimates. |
| XGBoost | Adds trees sequentially to reduce the training loss left by earlier trees. |
| K-Nearest Neighbors | Finds nearby training examples in the transformed feature space and combines their labels. The capture model gives nearer neighbors greater weight. |
| RF + XGBoost + KNN ensemble | Averages the three members' class probabilities and selects the strongest class after applying validation-derived Normal and alert rules. |

| Study | Training file and rows in scope | Testing file and rows | Task |
|---|---|---|---|
| UNSW-NB15 full-feature | `UNSW_NB15_training-set.csv`, 175,341 | `UNSW_NB15_testing-set.csv`, 82,332 | Ten categories, 42 offline predictors |
| UNSW-NB15 capture features | Same training file, 143,229 TCP/UDP flows | Same testing file, 72,513 TCP/UDP flows | Ten categories, deployment study |
| Independent NSL-KDD | `KDDTrain+.txt`, 125,973 | `KDDTest+.txt`, 22,544 | Normal versus Attack |

KNN fits a seeded stratified subset of 30,000 capture rows or 10,000 rows in the other studies. Every algorithm in each study is scored on that study's complete test split. **Model analytics** lets you switch benchmark and algorithm, compare the candidates, inspect per-class results and open the confusion matrix.

| Algorithm | Full UNSW accuracy / macro-F1 | Capture UNSW accuracy / macro-F1 | Binary NSL-KDD accuracy / macro-F1 |
|---|---:|---:|---:|
| Random Forest | 76.47% / .479 | 81.38% / .562 | 77.31% / .772 |
| XGBoost | 77.08% / .511 | 82.36% / .555 | 79.45% / .794 |
| KNN | 66.66% / .366 | 76.67% / .450 | 77.31% / .772 |
| RF + XGBoost + KNN ensemble | Not applicable | 81.97% / .562 | Not applicable |

These accuracy and macro-F1 figures describe the highest-scoring class before deployment rules. Accuracy counts correct predictions across rows. Macro-F1 gives each class equal weight. Precision measures how often a prediction for a class is correct. Recall measures how many actual examples of that class the model found. In the confusion matrix, each row is a true class and each column a predicted class.

### Why accuracy improved and where errors remain

Service and directional IP bytes helped distinguish flows with similar packet counts and durations. On the same grouped holdout, XGBoost macro-F1 rose from .238 with seven inputs to .627 with enriched inputs and .667 with enriched inputs plus SMOTENC. On the official test set it scored .555. Rare classes remain hard to distinguish. For instance, XGBoost correctly classified 237 of 1,224 DoS rows and zero of 58 Analysis rows. [Detailed evaluation](reports/evaluation/RESULTS.md)

**Why ordinary traffic sometimes looks suspicious.** An encrypted QUIC session, a short DNS exchange and a partial TCP connection can differ from the traffic measured by the original dataset exporter. In `firsttime.pcapng`, 12 one-request/one-reply DNS flows, four QUIC flows and three TCP flows fell outside training coverage. Its remaining flow received an unconfirmed Fuzzers alert. That recording has no supplied attack annotations. In contrast, the controlled HTTP recording at the top of this guide received a Normal prediction.

For covered flows, the deployed policy can choose Normal when it ranks second and its score is sufficiently close to the top attack category. Each model learns that gap using only labeled UNSW validation rows. The selected gap permits at most two percentage points of lost attack recognition on that validation partition. On the official test split, the weighted ensemble recognized **29,577 of 35,945** labeled Normal flows after the rule, up from **27,433** within the same coverage. It also reassigned **767 true attack flows** to Normal, which documents the cost of reducing false alarms. Separately, **12.14% of Normal flows raised alerts** and **85.92% of attack flows raised alerts**. The false-alarm target on validation was 5%.

### External capture checks

The frozen UNSW pipeline also read two USTC-TFC2016 captures. Their publisher labels describe each file as a whole. Neither file contributed training rows or decision thresholds. [External measurements](reports/evaluation/external_pcap_checks.json)

| File | Publisher group | Assessed / total flows | Predicted Normal | Alerts |
|---|---|---:|---:|---:|
| `Gmail.pcap` | Benign | 143 / 8,629 | 139 | 0 |
| `Tinba.pcap` | Malware | 1,471 / 10,641 | 159 | 4 |

The improved frozen ensemble raised no alerts on the 143 assessed Gmail flows; four below-threshold Worms predictions remain visible for review. The Tinba recording supports a demonstration of alert investigation, but its four alerts do not establish a per-flow malware-family label. A malware family name cannot establish a matching UNSW category for an individual flow.

## Stage demonstration with Wireshark

**1. Show a known ordinary exchange.** Upload `datasets/pcap_samples/ordinary-http.pcapng` using Automatic. Open its Normal flow and inspect frame 4 in the original file. It contains the local HTTP GET. The capture includes the response and TCP close. The measured ensemble result for this file is one assessed flow, score .8919, zero alerts.

**2. Capture one ordinary request live.** On Linux, run the following in a terminal. It serves a small file from a temporary directory on loopback.

```bash
demo_dir=$(mktemp -d)
printf 'AI-NIDS HTTP demonstration\n' > "$demo_dir/demo"
python3 -m http.server 8000 --bind 127.0.0.1 --directory "$demo_dir"
```

In Wireshark, select the loopback interface `lo`. Set the **capture filter** to `host 127.0.0.1 and tcp port 8000` and start recording. In a second terminal, run `curl --noproxy '*' http://127.0.0.1:8000/demo` once. Stop recording, save as `stage-http.pcapng`, then stop the HTTP server with Ctrl+C. Use the **display filter** `http.request` to locate the GET and `tcp.stream eq 0` to inspect the conversation when it is stream 0. Upload the new file. Live timing, packet segmentation and the resulting prediction can vary. The saved example supports an offline presentation if interface permissions or live results differ. [Wireshark capture filters](https://www.wireshark.org/docs/wsug_html_chunked/ChCapCaptureFilterSection.html) · [Wireshark display filters](https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html)

**3. Demonstrate attack investigation offline.** Upload `datasets/ustc_tfc2016/Tinba.pcap`. Open one of the four alerted **Fuzzers** flows and follow its original frame number in Wireshark using `frame.number == N` with the displayed integer. Open **Statistics → I/O Graphs** to inspect traffic volume over time. Describe the visible packet evidence and the model's category separately. To demonstrate categories with labeled benchmark rows, open **Model analytics → UNSW-NB15 · capture features → XGBoost → Confusion matrix**. The DoS and Exploits rows show both correct and missed detections. UNSW has a DoS category. Establishing distributed denial of service additionally requires evidence of coordinated sources and service impact. [Wireshark I/O graphs](https://www.wireshark.org/docs/wsug_html_chunked/ChStatIOGraphs.html)

**4. Reset for the next file.** Export a flow CSV if you want the numbers for your slides, then use **Clear this result**. The overview and analytics history reflect the cleared result immediately.

## Project file hierarchy

Generated caches such as `.venv/`, `__pycache__/` and `.pytest_cache/` are omitted below because they do not implement project behavior.

```text
AI-NIDS/
├── run_nids.py                         # Starts the local Flask dashboard
├── README.md                           # Complete setup, design, evaluation and demo guide
├── README_FASTTRACK.md                 # Short run and reproduction guide
├── requirements.txt                    # Reproducible Python dependencies
├── AbdulSami_ProjectProposal.pdf       # Approved project proposal
│
├── dashboard/
│   ├── fast_app.py                     # HTTP routes: upload, analysis, clearing and analytics
│   ├── analysis.py                     # Background PCAP-analysis job execution
│   ├── database.py                     # SQLite schema and persistence operations
│   ├── reports.py                      # Result/export helpers
│   ├── static/nids.css                 # Dashboard styling
│   └── templates/                      # Overview, capture, flow, analytics and clear-result pages
│
├── src/
│   ├── data/
│   │   ├── analyze_dataset.py          # Dataset exploration utilities
│   │   ├── inspect_dataset.py          # Dataset/schema inspection
│   │   └── nsl.py                      # NSL-KDD column and label handling
│   ├── preprocessing/
│   │   ├── preprocess.py               # UNSW loading and preprocessing definitions
│   │   └── feature_config.py           # Feature/category constants
│   ├── traffic/
│   │   ├── tshark_extractor.py         # Reads decoded frame fields using TShark
│   │   ├── flow_builder.py             # Groups frames into bidirectional timed flows
│   │   └── pcap_engine.py              # Produces model features and packet-to-flow mappings
│   ├── models/
│   │   ├── benchmark.py                # Three-model full-feature UNSW benchmark
│   │   ├── benchmark_nsl_kdd.py        # Independent three-model NSL-KDD benchmark
│   │   └── train_pcap_suite.py         # Tunes and publishes deployable UNSW capture models
│   ├── prediction/
│   │   ├── ensemble.py                 # Serializable validation-weighted ensemble
│   │   ├── model_loader.py             # Model registry names and artifact hashing
│   │   ├── pcap_service.py             # Artifact verification, coverage and decision policy
│   │   └── predict_pcap.py             # Command-line PCAP inference and CSV output
│   └── evaluation/
│       └── check_external_pcaps.py      # Separate inference-only USTC PCAP evaluation
│
├── datasets/
│   ├── unsw_nb15/                      # Primary official train/test CSVs and feature dictionary
│   ├── nsl_kdd/                        # Secondary independent train/test TXT files
│   ├── pcap_samples/                   # Inference-only local Wireshark examples
│   └── ustc_tfc2016/                   # Optional inference-only external PCAP samples
│
├── artifacts/
│   ├── models/
│   │   ├── capture_ensemble.joblib     # Default RF + XGBoost + KNN capture pipeline
│   │   ├── capture_random_forest.joblib
│   │   ├── capture_xgboost.joblib
│   │   ├── capture_knn.joblib
│   │   └── nsl_kdd_*.joblib            # Independent binary benchmark pipelines
│   └── registry/full/                  # Full-feature UNSW benchmark artifacts and metadata
│
├── reports/
│   ├── evaluation/                     # Metrics, class reports, matrices and external checks
│   ├── pcap_analysis/                  # CLI-generated flow and packet investigation CSVs
│   └── figures/                        # Dataset-analysis plots
│
├── docs/
│   ├── FEATURE_AND_ACCURACY_LIMITATIONS.md  # Active PCAP feature contract and limitations
│   ├── feature_compatibility.md              # Historical/compatibility analysis
│   └── project_limitations.md                # Evidence and interpretation guidance
│
├── storage/
│   ├── ai_nids.sqlite3                 # Local dashboard jobs, flows and result metadata
│   └── captures/                       # Retained original uploaded capture files
│
└── tests/
    ├── test_pcap_engine.py             # Extraction and flow-building regression tests
    ├── test_pcap_service.py            # Inference, coverage and Normal-rule tests
    ├── test_capture_upload.py           # Dashboard upload, result and clearing tests
    └── test_project_contract.py        # Dataset/model contract and removed-live-route checks
```

The most important execution chain is:

```text
run_nids.py
  -> dashboard/fast_app.py
  -> dashboard/analysis.py
  -> src/traffic/pcap_engine.py
  -> src/traffic/tshark_extractor.py + flow_builder.py
  -> src/prediction/pcap_service.py
  -> artifacts/models/capture_ensemble.joblib
  -> storage/ai_nids.sqlite3 + dashboard result pages
```

## Reproduce the work

Run these commands from the project root. The primary capture training command publishes Random Forest, XGBoost, KNN and ensemble files under `artifacts/models/`. `firsttime.pcapng`, `ordinary-http.pcapng`, and the USTC captures are inference checks only. The training scripts never read them.

```bash
.venv/bin/python -m src.models.benchmark --family full --retrain
.venv/bin/python -m src.models.train_pcap_suite
.venv/bin/python -m src.models.benchmark_nsl_kdd
.venv/bin/python -m src.evaluation.check_external_pcaps
.venv/bin/python -m src.prediction.predict_pcap --pcap datasets/pcap_samples/ordinary-http.pcapng
.venv/bin/python -m pytest -q
```

The CLI writes flow results and packet-to-flow mappings under `reports/pcap_analysis/<capture-name>/`. The dashboard uses the published capture suite at `reports/evaluation/pcap_suite.json`. The full benchmark records data sources and artifacts under `artifacts/registry/full/`. NSL-KDD has its own report at `reports/evaluation/nsl_kdd_suite.json`. The [capture engine](src/traffic/pcap_engine.py), [inference service](src/prediction/pcap_service.py) and [training script](src/models/train_pcap_suite.py) implement the path from measurements to predictions.
