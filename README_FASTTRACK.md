# AI-NIDS installation, training and demonstration guide

This guide takes a new user from an empty Python environment to a running dashboard, trained models, verified tests and Wireshark-file analysis. The detailed design, category definitions, measured limitations and project hierarchy are in [README.md](README.md).

## 1. What the project accepts

The dashboard accepts only:

- `.pcap` and `.pcapng` Wireshark capture files;
- `.csv` files containing the ten deployment flow features listed below.

Every accepted upload runs Random Forest, XGBoost, KNN and the validation-weighted ensemble. The result page provides a tab for each model. PCAP packets are first grouped into bidirectional TCP/UDP flows; every packet displayed under a flow inherits that flow's result. The models do not classify raw packet payload bytes independently.

Required CSV columns:

```text
proto,dur,spkts,dpkts,sinpkt,dinpkt,is_sm_ips_ports,service,sbytes,dbytes
```

`proto` must be `tcp` or `udp`. Numeric values must be finite and nonnegative. `spkts`, `dpkts`, and `is_sm_ips_ports` must be integers, and `is_sm_ips_ports` must be 0 or 1. Endpoint and time columns are optional. CSV files have no original packet records, so Wireshark frame investigation is available only for PCAP/PCAPNG uploads.

## 2. Install system software

### Ubuntu or Debian

From a terminal:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip wireshark tshark git
python3 --version
tshark --version
```

If the Wireshark package asks whether non-root users may capture packets, choose the option appropriate for your own machine and security policy. The AI-NIDS application only reads saved files; it does not perform live capture.

### Windows

1. Install Python and enable **Add Python to PATH** during setup.
2. Install Wireshark with TShark and Npcap enabled in its installer.
3. Install Git if the project will be cloned.
4. Open PowerShell and verify:

```powershell
python --version
tshark --version
git --version
```

If PowerShell cannot find TShark, add the Wireshark installation directory to `PATH` or restart the terminal after installation.

## 3. Open the project and create the environment

These Linux/macOS commands assume the repository is already available:

```bash
cd /path/to/AI-NIDS
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install pytest
```

PowerShell equivalent:

```powershell
cd C:\path\to\AI-NIDS
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install pytest
```

Verify the important imports:

```bash
python -c "import flask, pandas, sklearn, xgboost, imblearn, joblib; print('Python dependencies OK')"
tshark --version
```

Use `requirements.txt` for the recorded project environment. `requirements_fasttrack.txt` is a smaller compatibility list, not the authoritative reproducibility lock.

## 4. Place the proposal datasets

Training is restricted to UNSW-NB15 and NSL-KDD:

```text
datasets/
├── unsw_nb15/
│   ├── UNSW_NB15_training-set.csv
│   ├── UNSW_NB15_testing-set.csv
│   └── NUSW-NB15_features.csv
└── nsl_kdd/
    ├── KDDTrain+.txt
    └── KDDTest+.txt
```

Download UNSW-NB15 from the [official UNSW research dataset page](https://research.unsw.edu.au/projects/unsw-nb15-dataset). That page provides the official train/test CSV partitions and also links the much larger raw PCAP, Argus, Bro and ground-truth material.

Download NSL-KDD from the [official UNB/CIC dataset page](https://www.unb.ca/cic/datasets/nsl.html). Preserve the exact `KDDTrain+.txt` and `KDDTest+.txt` filenames.

Confirm that the expected files exist:

```bash
ls -lh datasets/unsw_nb15/UNSW_NB15_training-set.csv
ls -lh datasets/unsw_nb15/UNSW_NB15_testing-set.csv
ls -lh datasets/nsl_kdd/KDDTrain+.txt
ls -lh datasets/nsl_kdd/KDDTest+.txt
```

Do not train on `firsttime.pcapng`, downloaded malware captures or ordinary local captures. PCAPs are inference/external-validation evidence unless a separate, approved experiment supplies reliable flow-level labels and a leakage-safe split.

## 5. Train all retained models

Run the commands from the repository root with the virtual environment active.

### A. Train the deployable UNSW capture-feature suite

```bash
python -m src.models.train_pcap_suite
```

This command:

- keeps TCP/UDP rows from the official UNSW training split;
- compares the seven-feature baseline, enriched inputs, and capped SMOTENC targets of 600, 1,200 and 2,400 using grouped validation;
- trains Random Forest, XGBoost and KNN;
- chooses each model's imbalance configuration using validation results;
- selects ensemble weights from validation predictions;
- freezes coverage, Normal-margin and alert-threshold rules;
- evaluates once on the official UNSW testing split;
- publishes the active report and four deployment artifacts.

Expected files:

```text
artifacts/models/capture_random_forest.joblib
artifacts/models/capture_xgboost.joblib
artifacts/models/capture_knn.joblib
artifacts/models/capture_ensemble.joblib
reports/evaluation/pcap_suite.json
```

### B. Train the full-feature UNSW benchmark

```bash
python -m src.models.benchmark --family full --retrain
```

This benchmark uses the 42 offline UNSW predictors. It is useful for proposal evaluation, but it cannot classify arbitrary PCAP uploads because many exporter/history features cannot be recreated from an isolated capture.

### C. Train the independent NSL-KDD benchmark

```bash
python -m src.models.benchmark_nsl_kdd
```

NSL-KDD has different features and a binary Normal/Attack target. Its models are independent and never vote on Wireshark uploads. Expected files:

```text
artifacts/models/nsl_kdd_random_forest.joblib
artifacts/models/nsl_kdd_xgboost.joblib
artifacts/models/nsl_kdd_knn.joblib
reports/evaluation/nsl_kdd_suite.json
```

## 6. Run automated tests and inspect evaluation

```bash
python -m pytest -q
python -m compileall -q dashboard src tests
```

The current project should report 22 passing tests. Review the saved metrics:

```bash
python - <<'PY'
import json

report = json.load(open("reports/evaluation/pcap_suite.json"))
for name, record in report["models"].items():
    metrics = record["test"]
    deployment = metrics["deployment"]
    print(
        name,
        "accuracy=", round(metrics["accuracy"], 4),
        "macro_f1=", round(metrics["macro_f1"], 4),
        "normal_alert_rate=", round(deployment["false_alarms_per_normal_flow"], 4),
        "attack_alert_recall=", round(deployment["alerts_per_attack_flow"], 4),
    )
PY
```

The detailed human-readable summary is [reports/evaluation/RESULTS.md](reports/evaluation/RESULTS.md). The dashboard's **Model analytics** page shows per-class precision, recall, F1 and confusion matrices.

## 7. Start the dashboard

Linux/macOS:

```bash
source .venv/bin/activate
python run_nids.py
```

Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
python run_nids.py
```

Open [http://127.0.0.1:5000](http://127.0.0.1:5000).

Upload a `.pcap`, `.pcapng`, or compatible `.csv`. One upload automatically runs:

1. Random Forest;
2. XGBoost;
3. KNN;
4. RF + XGBoost + KNN weighted ensemble.

Use the model tabs to compare the same flow across all four results. The ensemble is the default SOC view. The queue displays alerts first, assessed attack-category predictions second, outside-coverage triage suggestions third and assessed Normal flows last.

Existing results saved before multi-model support must be cleared and uploaded again.

## 8. Command-line PCAP analysis

Analyze with the ensemble:

```bash
python -m src.prediction.predict_pcap \
  --pcap datasets/pcap_samples/ordinary-http.pcapng \
  --model ensemble
```

Choose one model explicitly:

```bash
python -m src.prediction.predict_pcap --pcap capture.pcapng --model random_forest
python -m src.prediction.predict_pcap --pcap capture.pcapng --model xgboost
python -m src.prediction.predict_pcap --pcap capture.pcapng --model knn
```

Results are written under `reports/pcap_analysis/<capture-name>/`:

- `flow_predictions.csv`: one reconstructed flow per row;
- `packet_investigation.csv`: original frame-to-flow mapping and inherited flow result.

The command-line tool runs the selected model. The dashboard is the convenient way to run and compare all four models in one upload.

## 9. Create a normal PCAP with Wireshark

The application has no live-capture feature. Capture manually in Wireshark:

1. Open Wireshark.
2. Select the active Ethernet/Wi-Fi interface, or `lo`/loopback for a local-only demonstration.
3. Optionally enter a narrow capture filter, such as `tcp port 8000`.
4. Start capture.
5. Perform an ordinary action you understand, such as opening one test webpage or calling a local HTTP server.
6. Stop capture.
7. Choose **File → Save As** and save as `.pcapng` or `.pcap`.
8. Upload the saved file to AI-NIDS.

Wireshark documents `.pcapng` as its native/default format and supports saving as `.pcap` through **File → Save** or **Save As**. See the [official Wireshark saving guide](https://www.wireshark.org/docs/wsug_html/index.html#ChIOSaveSection).

Safe loopback example:

```bash
demo_dir=$(mktemp -d)
printf 'AI-NIDS demonstration\n' > "$demo_dir/demo"
python3 -m http.server 8000 --bind 127.0.0.1 --directory "$demo_dir"
```

Capture `tcp port 8000` on loopback, then run in another terminal:

```bash
curl --noproxy '*' http://127.0.0.1:8000/demo
```

Stop and save the capture, then stop the server with Ctrl+C. A ready-made version is available at `datasets/pcap_samples/ordinary-http.pcapng`.

## 10. Obtain PCAPs containing attack-related traffic

Use published research captures rather than attacking public systems or generating disruptive traffic. Only run security experiments on systems and networks you own or are explicitly authorized to test.

### Official UNSW-NB15 raw PCAPs

The [UNSW-NB15 official page](https://research.unsw.edu.au/projects/unsw-nb15-dataset) states that its raw capture material contains Normal traffic and nine attack families: Analysis, Backdoor, DoS, Exploits, Fuzzers, Generic, Reconnaissance, Shellcode and Worms. The raw collection is approximately 100 GB, so download only if storage and bandwidth permit.

Important: a raw UNSW PCAP does not place an attack-category label inside every packet. Reliable validation requires the matching UNSW ground-truth/event files, timestamps, endpoints and original flow-generation conventions. Uploading a raw file to this project produces predictions; it does not automatically recover the official label for every reconstructed flow.

### USTC-TFC2016 optional external captures

The [USTC-TFC2016 repository](https://github.com/davidyslu/USTC-TFC2016) contains benign application PCAPs and malware-family PCAPs. To download the repository:

```bash
tmp_dataset_dir=$(mktemp -d)
git clone --depth 1 https://github.com/davidyslu/USTC-TFC2016.git "$tmp_dataset_dir/USTC-TFC2016"
mkdir -p datasets/ustc_tfc2016
cp "$tmp_dataset_dir/USTC-TFC2016/Benign/Gmail.pcap" datasets/ustc_tfc2016/
cp "$tmp_dataset_dir/USTC-TFC2016/Malware/Tinba.pcap" datasets/ustc_tfc2016/
```

Run the separate external check:

```bash
python -m src.evaluation.check_external_pcaps
```

Results are written to `reports/evaluation/external_pcap_checks.json` and are not mixed with UNSW or NSL-KDD metrics.

USTC filenames/group folders provide capture-level benign or malware-family context. They do **not** prove that an individual flow belongs to an UNSW category. For example, `Tinba.pcap` must not be called a verified UNSW DoS or Fuzzers capture without matching per-flow evidence.

### What to use for a stage presentation

- Normal demonstration: `datasets/pcap_samples/ordinary-http.pcapng`.
- Personal-network demonstration: a short, manually saved Wireshark capture, described as unlabeled live-environment traffic.
- External alert investigation: `datasets/ustc_tfc2016/Tinba.pcap`, with the publisher's malware-family context reported separately from the model's UNSW prediction.
- Ground-truth category performance: use **Model analytics → UNSW-NB15 capture features → model → Confusion matrix**, because those rows have official labels.

Do not claim that every packet in a downloaded malware capture has a verified UNSW attack category. The project categorizes reconstructed flows and links their results back to packets for investigation.

## 11. Reproduce external checks and final verification

```bash
python -m src.evaluation.check_external_pcaps
python -m src.prediction.predict_pcap \
  --pcap datasets/pcap_samples/ordinary-http.pcapng \
  --model ensemble
python -m pytest -q
python run_nids.py
```

Expected ordinary sample behavior for the current saved release:

```text
12 captured frames
1 reconstructed flow
Normal prediction
0 alerts
```

Exact scores can change after an approved retraining run. Always use the saved evaluation report associated with the active artifact.

## 12. Common problems

### `tshark: command not found`

Install Wireshark/TShark and verify that `tshark` is on `PATH`.

### Missing dataset file

Check the exact folder and case-sensitive filename shown in section 4.

### CSV rejected

Confirm all ten required columns are present, protocol values are TCP/UDP, numeric columns contain no blanks/NaN/infinity/negative values and the file has no more than 100,000 rows.

### Most flows are Unassessed

This means the flow's service or directional packet-count range is outside observed UNSW training coverage. It is not an attack label. The SOC queue still shows a provisional model lead for prioritization, but outside-coverage flows cannot alert.

### Old capture does not show four model tabs correctly

Clear the old stored result and upload the original file again. Multi-model predictions are saved at upload time.

### Port 5000 is already in use

Stop the older AI-NIDS process before starting a new one. Do not run two dashboard instances against the same SQLite file.

## 13. One-command checklist

After dependencies and datasets are present:

```bash
source .venv/bin/activate
python -m src.models.train_pcap_suite
python -m src.models.benchmark --family full --retrain
python -m src.models.benchmark_nsl_kdd
python -m src.evaluation.check_external_pcaps
python -m pytest -q
python run_nids.py
```

Then open [http://127.0.0.1:5000](http://127.0.0.1:5000), upload an allowed file and compare all four model tabs.
