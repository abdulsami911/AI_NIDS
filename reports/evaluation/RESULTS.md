# AI-NIDS evaluation

## Primary benchmark: UNSW-NB15

Random Forest, XGBoost and KNN were fitted only on the official training split. The full-feature benchmark uses 175,341 training and 82,332 testing connections with 42 predictors. The deployable capture study uses 143,229 training and 72,513 testing TCP/UDP connections with measurements reproducible from TShark. PCAP files supplied for inference are not training data.

| Algorithm | Full-feature accuracy | Full-feature macro-F1 | Capture accuracy | Capture macro-F1 |
|---|---:|---:|---:|---:|
| Random Forest | 76.47% | .479 | 82.81% | .561 |
| XGBoost | 77.08% | .511 | 82.36% | .555 |
| KNN | 66.66% | .366 | 77.63% | .455 |
| Validation-weighted ensemble | Not applicable | Not applicable | 81.97% | .562 |

The three base models compared a seven-feature baseline, enriched service/directional-byte inputs, and capped SMOTENC targets of 600, 1,200 and 2,400 applied to fit rows only. Their selected variants were refitted on the training split. Grouped validation selected ensemble weights of 50% Random Forest, 30% XGBoost and 20% KNN; the ensemble is not a fourth separately trained learner.

| Model | Selected validation macro-F1 | Normal test flows alerting | Attack test flows alerting |
|---|---:|---:|---:|
| Random Forest | .656 | 15.99% | 90.94% |
| XGBoost | .667 | 12.44% | 86.76% |
| KNN | .575 | 9.56% | 79.15% |
| Ensemble | .676 | 12.14% | 85.92% |

Accuracy and macro-F1 use the highest-scoring category. Alert rates additionally apply the validation-derived Normal rule, training-coverage check and alert threshold. The full confusion matrices, per-class precision/recall/F1, hashes, thresholds and counts are in [pcap_suite.json](pcap_suite.json) and the [full-feature registry](../../artifacts/registry/full/).

## Secondary independent benchmark: NSL-KDD

These are separately fitted binary Normal/Attack pipelines using 125,973 training and 22,544 testing rows. They do not modify or validate the UNSW category models.

| Algorithm | Accuracy | Macro-F1 | Attack precision | Attack recall |
|---|---:|---:|---:|---:|
| Random Forest | 77.31% | .772 | 96.83% | 62.17% |
| XGBoost | 79.45% | .794 | 96.86% | 66.04% |
| KNN | 77.31% | .772 | 96.63% | 62.31% |

Full details and hashes are in [nsl_kdd_suite.json](nsl_kdd_suite.json).

## External PCAP validation

USTC-TFC2016 `Gmail.pcap` and `Tinba.pcap` are inference-only checks. They did not affect fitting, preprocessing, thresholds or saved parameters. Their publisher labels apply to whole files, so a malware-family filename is not treated as evidence for a particular UNSW attack category. Results are reported separately in [external_pcap_checks.json](external_pcap_checks.json).

The user's `firsttime.pcapng` is also inference-only. It has no supplied attack annotations; therefore its one alert remains unconfirmed, and its other flows may correctly be shown as Unassessed when their feature combinations lack training coverage.
