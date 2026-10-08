# ForenSight 
### A Forensic-Ready Hybrid Intrusion Detection System

> **Detect it. Explain it. Prove it.**
> ForenSight catches network attacks with three complementary detectors, explains every alert, and stores each alert in a tamper-evident evidence log that an investigator can verify.

**Course:** Cyber Security, Theory CA-2 (Part 2), Unit 4 Case Study
**Group:** `[G__]`  |  **Members:** `[Member 1]`, `[Member 2]`, `[Member 3]`, `[Member 4]`
**Faculty:** Dr. Pooja Bagane, Dr. Jitendra Rajpurohit

---

## 📌 Table of Contents
1. [What the project does](#-what-the-project-does)
2. [How it maps to Unit 4](#-how-it-maps-to-unit-4)
3. [System architecture](#-system-architecture)
4. [Project structure](#-project-structure)
5. [Requirements](#-requirements)
6. [Installation](#-installation)
7. [How to run](#-how-to-run)
8. [Expected output](#-expected-output)
9. [Output files explained](#-output-files-explained)
10. [How the code works (step by step)](#-how-the-code-works-step-by-step)
11. [Results](#-results)
12. [Customising the project](#-customising-the-project)
13. [Troubleshooting](#-troubleshooting)
14. [Limitations and future work](#-limitations-and-future-work)
15. [References](#-references)

---

##  What the project does

Most intrusion detection systems (IDS) have three weaknesses:

| Problem | What goes wrong | How ForenSight fixes it |
|---|---|---|
| **New (zero-day) attacks** | Signature rules only know old attacks, and ML models trained on old data miss new ones | Three detectors: **rules + XGBoost + Isolation Forest**. The Isolation Forest is trained only on normal traffic, so it flags anything unusual |
| **No explanation** | ML says "92% attack" but not *why* | **SHAP** stores the top-3 reasons with every alert |
| **Evidence can be erased** | A hacker with admin rights deletes the alert logs | **SHA-256 hash chain + HMAC-signed anchors** make any edit, deletion or re-ordering detectable |

---

##  How it maps to Unit 4

| Unit 4 topic | Where it appears in the code |
|---|---|
| **Intrusion Detection System**: signature vs anomaly, alerts, false positives | Tier 1 rules, Tier 2/3 models, fusion with a 3% false-positive budget |
| **Malware Analysis**: attack behaviour, MITRE ATT&CK, zero-day | 12 rules describing attack/malware behaviour (root shell, brute force, warez upload), each tagged with an ATT&CK ID; evaluation on 17 unseen attack types |
| **Digital Forensics**: identify → preserve → collect → analyse → document → present | Hash-chained evidence log, HMAC anchors, verification algorithm, SHAP evidence fields |
| **Dark Web**: leaked credentials, Tor anonymity | Threat model: leaked passwords drive brute-force (R2L) attacks, caught by rule `SIG-07`; anonymity makes trustworthy local evidence essential |

---

##  System architecture

```
          ┌───────────────────────────────────────┐
          │  Network flow record (41 features)    │
          └───────────────────┬───────────────────┘
                              ▼
          ┌───────────────────────────────────────┐
          │  Preprocessing                        │
          │  one-hot · log(1+x) · min-max scaling │
          └───────────────────┬───────────────────┘
          ┌───────────────────┼───────────────────┐
          ▼                   ▼                   ▼
 ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
 │ Tier 1          │ │ Tier 2          │ │ Tier 3          │
 │ 12 signature    │ │ XGBoost         │ │ Isolation Forest│
 │ rules → ATT&CK  │ │ p(attack|flow)  │ │ (normal only)   │
 └────────┬────────┘ └────────┬────────┘ └────────┬────────┘
          └───────────────────┼───────────────────┘
                              ▼
          ┌───────────────────────────────────────┐
          │  Fusion: alert if ANY tier fires      │
          │  FPR ≤ 3% · severity HIGH/MEDIUM/LOW  │
          └───────────────────┬───────────────────┘
                              ▼
          ┌───────────────────────────────────────┐
          │  SHAP: top-3 reasons for the alert    │
          └───────────────────┬───────────────────┘
                              ▼
          ┌───────────────────────────────────────┐
          │  Forensic evidence log                │
          │  H_i = SHA256(record_i ‖ H_(i-1))     │
          │  + HMAC anchor every 1,000 alerts     │
          └───────────────────┬───────────────────┘
                              ▼
          Investigator verifies → INTACT  or  "tampered at entry #k"
```

---

## Project structure

```
ForenSight/
├── README.md            ← this file
├── requirements.txt     ← Python libraries needed
├── download_data.py     ← downloads the NSL-KDD dataset into data/
├── forensight.py        ← the full system: detection, explanation, evidence log, evaluation
├── data/                ← created by download_data.py
│   ├── KDDTrain+.txt    (125,973 records)
│   └── KDDTest+.txt     (22,544 records)
└── out/                 ← created by forensight.py (results, figures, alert log sample)
```

---

##  Requirements

| Item | Version |
|---|---|
| Python | **3.9 or newer** (tested on 3.13) |
| RAM | 4 GB minimum (8 GB recommended) |
| Disk | ~100 MB (dataset + libraries + outputs) |
| GPU | **Not needed**, runs on any laptop CPU |
| Internet | Only once, to install libraries and download the dataset |

Python libraries (installed automatically from `requirements.txt`):
`numpy`, `pandas`, `scikit-learn`, `xgboost`, `shap`, `matplotlib`

---

##  Installation

### 1. Get the project
Unzip the project folder and open a terminal **inside** the `ForenSight` folder.

### 2. Create a virtual environment (recommended)

**Windows (Command Prompt / PowerShell)**
```bash
python -m venv venv
venv\Scripts\activate
```

**macOS / Linux**
```bash
python3 -m venv venv
source venv/bin/activate
```

You should now see `(venv)` at the start of your terminal line.

### 3. Install the libraries
```bash
pip install -r requirements.txt
```

### 4. Download the dataset
```bash
python download_data.py
```
Expected output:
```
Downloading KDDTrain+.txt ...
  data/KDDTrain+.txt: 125973 records  [OK]
Downloading KDDTest+.txt ...
  data/KDDTest+.txt: 22544 records  [OK]
Dataset ready.
```

> **No internet / download blocked?** Download `KDDTrain+.txt` and `KDDTest+.txt` manually from
> https://github.com/defcom17/NSL_KDD (or the official source: https://www.unb.ca/cic/datasets/nsl.html)
> and place both files in a folder called `data/` inside the project.

---

##  How to run

```bash
python forensight.py
```

That's it. The single command runs the **entire pipeline**: training, detection, explanation, evidence logging, tamper testing, evaluation and figure generation.

 Runtime: **about 2–4 minutes** on a normal laptop.

Optional: choose your own input and output folders:
```bash
python forensight.py <data_folder> <output_folder>
# example
python forensight.py data results_run2
```

> On macOS/Linux use `python3` instead of `python` if `python` is not found.

---

##  Expected output

```
[ForenSight] Loading NSL-KDD ...
[ForenSight] Running Tier 1 signature engine ...
[ForenSight] Training Tier 2 classifiers (takes 1-3 minutes) ...
[ForenSight]   Logistic Regression  test accuracy = 74.56%
[ForenSight]   Decision Tree        test accuracy = 78.94%
[ForenSight]   Random Forest        test accuracy = 78.72%
[ForenSight]   MLP (64-32)          test accuracy = 79.60%
[ForenSight]   XGBoost              test accuracy = 79.20%
[ForenSight] Training Tier 3 Isolation Forest on benign traffic ...
[ForenSight] Fusion thresholds chosen on validation: XGBoost t = 0.45, IForest quantile = 0.99
[ForenSight] Training 5-class attack-family model ...
[ForenSight] Computing SHAP explanations ...
[ForenSight] Building and attacking the tamper-evident evidence log ...

==============================================================
 ForenSight results on KDDTest+ (22,544 flows)
==============================================================
 Hybrid accuracy          :  87.23%   (XGBoost alone 79.20%)
 Hybrid F1 / FPR          : 0.878 / 3.88%
 Novel-attack recall      :  62.16%   (XGBoost alone 37.04%)
 KDDTest-21 accuracy      :  75.86%
 Evidence log             : 10708 alerts, verify = ok, 142.2 us/alert
 Tampering detected       : 1000/1000
==============================================================
 All outputs written to: .../ForenSight/out
```

 **Accuracy numbers are reproducible**: the random seed is fixed at 42, so you get the same detection results as in the report.
 Only the **timing** values (µs per alert) differ from machine to machine.
(Tiny differences in the last decimal are possible with very different library versions.)

---

##  Output files explained

All files are written to `out/`:

| File | What it contains | Used in report |
|---|---|---|
| `results.json` | **Every number** in the report: all metrics, rule hit counts, thresholds, ablation, SHAP ranking, tamper results | Tables 4, 9–12 |
| `roc.pdf / .png` | ROC curves for all models | Figure 3 |
| `ablation.pdf / .png` | Recall, novel-attack recall and FPR for each combination of detectors | Figure 4 |
| `cat_recall.pdf / .png` | Detection rate per attack family (DoS, Probe, R2L, U2R) and known vs new attacks | Figure 5 |
| `cm5.pdf / .png` | Confusion matrix of the 5-class attack-family model | Figure 6 |
| `shap.pdf / .png` | Top-15 features that drive the AI's decisions | Figure 7 |
| `alert_log_sample.jsonl` | First 5 records of the tamper-evident evidence log (with SHAP reasons and hashes) | Section 4.3 |

**Example evidence record** (from `alert_log_sample.jsonl`):
```json
{"seq": 0, "ts": 1791436800.0, "flow_id": 0, "proto": "tcp", "service": "private",
 "flag": "REJ", "src_bytes": 0, "dst_bytes": 0, "detector": "ML", "rules": [],
 "ml_score": 1.0, "anomaly": 0.5669, "severity": "HIGH",
 "evidence": ["src_bytes", "count", "service_private"],
 "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
 "hash": "05c1f94a925086a6e9bf2b196911de4f9b74084f78b19152b50624586395698c"}
```
Each record's `prev_hash` equals the previous record's `hash`. That link is what makes the log tamper-evident.

---

##  How the code works (step by step)

`forensight.py` is organised into seven clearly commented stages:

### Stage 0: Load and label data
Reads NSL-KDD, maps 39 attack names into 4 families (**DoS, Probe, R2L, U2R**), and marks the **17 attack types that exist only in the test set** as "novel" (our zero-day simulation).

### Stage 1: Preprocessing
- One-hot encodes `protocol_type`, `service`, `flag` → **121 features**
- Applies `log(1+x)` to heavy-tailed byte/count features
- Min-max scales to 0–1
- Splits training data **80% train / 20% validation** (stratified). The validation part is used **only** for tuning thresholds, and the test set is touched once at the end. This prevents "cheating".

### Stage 2: Tier 1, signature engine (12 rules)
| ID | Detects | ATT&CK |
|---|---|---|
| SIG-01 | SYN flood (half-open connections) | T1498/T1499 |
| SIG-02 | ICMP Smurf flood | T1498 |
| SIG-03 | Malformed fragments (Teardrop, Pod) | T1499 |
| SIG-04 | LAND attack | T1499 |
| SIG-05 | Port scan / sweep | T1046 |
| SIG-06 | ICMP host sweep | T1018 |
| SIG-07 | Brute-force login | T1110 |
| SIG-08 | Root shell obtained | T1068 |
| SIG-09 | su / root activity | T1548 |
| SIG-10 | Oversized HTTP request | T1190 |
| SIG-11 | Guest FTP write (warez) | T1105 |
| SIG-12 | Many "hot" indicators | T1059 |

### Stage 3: Tier 2, supervised ML
Trains **Logistic Regression, Decision Tree, Random Forest, MLP and XGBoost** for comparison. XGBoost is used as the Tier-2 detector (best validation accuracy and ROC-AUC).

### Stage 4: Tier 3, anomaly detector
An **Isolation Forest** trained **only on normal traffic**. Its threshold is calibrated from the score distribution of normal validation traffic.

### Stage 5: Fusion
```
ALERT  if  (any rule fires)  OR  (XGBoost score ≥ t)  OR  (anomaly score ≥ τ)
```
`t` and `τ` are chosen by grid search on **validation data only**, maximising F1 subject to **false-positive rate ≤ 3%**. Each alert gets a severity: **HIGH** (rule fired or score ≥ 0.9), **MEDIUM** (ML), **LOW** (anomaly only). The stage also runs an **ablation study** (every combination of tiers).

### Stage 6: Explainability
**TreeSHAP** ranks the features that pushed each prediction towards "attack". The top 3 are written into every evidence record.

### Stage 7: Forensic evidence log and tamper test
1. Every alert becomes a JSON record whose hash is `SHA256(record + previous hash)`.
2. Every 1,000 alerts an **anchor** `HMAC-SHA256(secret_key, hash)` is created (in real use stored off-host / in an HSM).
3. A verifier re-walks the chain and checks the anchors.
4. A **tamper harness** attacks a 2,000-alert log **1,000 times** (field edit, deletion, re-ordering, full re-hash, truncation) and records whether the verifier caught it.

---

##  Results

| Detector | Accuracy | Recall | F1 | False-positive rate |
|---|---|---|---|---|
| Signature rules only | 65.18% | 40.38% | 0.569 | 2.05% |
| XGBoost only | 79.20% | 65.58% | 0.782 | 2.80% |
| Isolation Forest only | 82.35% | 71.32% | 0.822 | 3.06% |
| **ForenSight hybrid** | **87.23%** | **80.50%** | **0.878** | 3.88% |

| Highlight | Value |
|---|---|
| New (unseen) attack types caught | **62.2%** (vs 37.0% for XGBoost alone) |
| Accuracy on hard subset KDDTest-21 | **75.9%** (vs 60.4%) |
| Tampering attempts detected | **1,000 / 1,000 (100%)** |
| Evidence log cost | ~0.14 ms and ~402 bytes per alert |

---

##  Customising the project

| Want to… | Change this in `forensight.py` |
|---|---|
| Add a new signature rule (e.g. from dark-web threat intel) | Append a tuple to the `RULES` list: `("SIG-13", "description", "ATT&CK ID", lambda d: <condition>)` |
| Allow more / fewer false alarms | Change `mv["fpr"]<=0.03` in the fusion section |
| Seal the log more / less often | Change `% 1000` in `build_log` |
| Change the secret anchor key | Change `KEY = b"..."` (in real deployments load it from a secure vault, never hard-code it) |
| Try other random seeds | Change `SEED = 42` |

---

##  Troubleshooting

| Problem | Fix |
|---|---|
| `Missing data/KDDTrain+.txt` | Run `python download_data.py`, or download manually (see Installation step 4) |
| `ModuleNotFoundError: No module named 'xgboost'` (or `shap`) | Activate the virtual environment, then `pip install -r requirements.txt` |
| `pip` not found | Use `python -m pip install -r requirements.txt` |
| `python` not found (macOS/Linux) | Use `python3` |
| SHAP install fails on Windows | Run `pip install --upgrade pip setuptools wheel`, then retry |
| Script feels slow | Normal: training takes 1–3 min. Random Forest and MLP are the slowest steps |
| Font warning in figures | Harmless. Figures fall back to an available serif font |

---

##  Limitations and future work

- **Dataset age:** NSL-KDD comes from 1998 traffic with no encryption. Next step: CIC-IDS2017, UNSW-NB15 and live campus traffic (Zeek logs).
- **Blind spot:** SNMP attacks (`snmpguess`, `snmpgetattack`) look like normal flows, so no detector catches them without payload inspection.
- **Truncation window:** alerts after the last anchor need time-based anchoring.
- **Future:** feed dark-web leaked-credential alerts into the rule book, add host-level malware telemetry, and test robustness to adversarial evasion.

---

##  References

1. M. Tavallaee, E. Bagheri, W. Lu, A. A. Ghorbani, "A detailed analysis of the KDD CUP 99 data set," *IEEE CISDA*, 2009.
2. T. Chen, C. Guestrin, "XGBoost: A scalable tree boosting system," *ACM SIGKDD*, 2016.
3. F. T. Liu, K. M. Ting, Z.-H. Zhou, "Isolation forest," *IEEE ICDM*, 2008.
4. S. M. Lundberg, S.-I. Lee, "A unified approach to interpreting model predictions," *NeurIPS*, 2017.
5. B. Schneier, J. Kelsey, "Secure audit logs to support computer forensics," *ACM TISSEC*, 1999.
6. K. Kent et al., "Guide to integrating forensic techniques into incident response," *NIST SP 800-86*, 2006.
7. B. E. Strom et al., "MITRE ATT&CK: Design and philosophy," MITRE, 2018.

The full list of 50 references is in the project report (`G__.pdf`).

---

<p align="center"><b>ForenSight</b>: Detect it. Explain it. Prove it.</p>
