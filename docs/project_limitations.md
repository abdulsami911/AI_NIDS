# Interpreting an AI-NIDS investigation

This study describes the earlier four-feature registry model. The current upload dashboard uses the [capture suite and feature definitions](FEATURE_AND_ACCURACY_LIMITATIONS.md).

## What an alert establishes

A detection assigns a learned category to one reconstructed flow. Its original frame numbers, direction, packet lengths and timestamps establish what the sensor observed. An analyst still needs independent evidence, such as an endpoint event or an application log, to confirm a particular attack. This distinction applies to every packet in a suspicious flow. A Normal prediction can also hide an attack.

The displayed model score measures the classifier's support for its selected class under the fitted model. Tree votes, boosted probabilities and neighbor fractions have different statistical behavior. The ensemble averages the Random Forest, XGBoost and KNN probabilities. Class resampling changes the frequencies seen in training. Scores lack calibration on this sensor's real traffic. Use the class, model version and packet evidence together when documenting a finding. Alert severity represents a triage policy set by the operator.

## What four inputs can distinguish

Two flows with identical observed duration, protocol and directional packet counts present identical inputs to the deployed classifier, even if their payloads, endpoints and consequences differ. In the official training split **80,922 of 175,341 rows** share their exact four-feature vector with at least one differently labeled training row. The corresponding test count is **33,398 of 82,332**. These counts measure how many rows have ambiguous feature values.

For example, the training split contains 14,508 rows with protocol UDP, duration 0.000009 seconds, two source packets and zero destination packets. They include 12,010 Generic, 1,055 Reconnaissance, 802 Fuzzers, 390 Normal, 157 Shellcode, 51 Exploits, 40 DoS and 3 Worms. No classifier using just those four inputs can distinguish those rows from each other. To reproduce the counts from the project root, run the following inside the project environment.

```python
import pandas as pd

keys = ["dur", "proto", "spkts", "dpkts"]
for split in ["training", "testing"]:
    df = pd.read_csv(f"datasets/unsw_nb15/UNSW_NB15_{split}-set.csv")
    label_count = df.groupby(keys)["attack_cat"].transform("nunique")
    print(split, int((label_count > 1).sum()), len(df))
```

## Dataset and evaluation limits

- **Population shift.** UNSW-NB15 combines generated attacks with normal traffic from a cyber range. An encrypted video call, a software update or a file synchronization burst on a campus network can resemble a labeled training example. A score on the official testing CSV measures that benchmark. Ground-truth labels for the supplied local capture have not been established. [UNSW dataset](https://research.unsw.edu.au/projects/unsw-nb15-dataset)
- **Class imbalance.** There are 130 Worms examples before oversampling in training and 44 in testing. One extra correctly classified Worms row changes test recall by about 2.27 percentage points. Repeating training rows increases their training weight and leaves the number of independent examples unchanged. The class reports give the denominator for every recall.
- **Protocol coverage.** Training has just 15 `icmp` records, all Normal. The named official test split has zero `icmp` records. The benchmark cannot establish ICMP attack recall. The split also does not identify the IP version of each TCP and UDP row, so it cannot supply separate IPv6 performance estimates.
- **Model selection.** Comparing several models on one official test set makes the displayed winner a descriptive benchmark choice. Independent, labeled local captures or a separate holdout are needed for an unbiased estimate of deployed model performance. Accuracy and weighted F1 can obscure failures on rare classes.
- **Separate benchmark.** NSL-KDD derives from a different collection, with different measurements and labels. Its scores characterize that dataset. Neither its categories nor its fitted encodings translate directly to UNSW-NB15 data. [UNB NSL-KDD dataset description](https://www.unb.ca/cic/datasets/nsl.html)

## Capture and evidence limits

| Situation | Consequence for the investigation |
|---|---|
| The capture starts midstream, sees one direction, drops frames or stops early | Observed duration and counts can shrink. Sender/responder inference can reverse the apparent traffic direction. Zero reverse packets records what this sensor saw. |
| Timestamp resolution, unsynchronized capture clocks or host packet offload | Millisecond-scale burst shapes, segment counts and packet sizes can change between a host capture and a wire capture. |
| Long-lived sessions, NAT, tuple reuse or repeated UDP transactions | Timeout and session policies determine which frames form each record. An Argus exporter can use finer protocol-specific distinctions. [Argus sensor documentation](https://openargus.org/argus-ids) |
| Encapsulation, unsupported protocols or incomplete transport headers | Some frames cannot be assigned safely to a supported flow. Account for skipped frames alongside classified evidence and distinguish the capture's total frame count from the number assigned to flows. |
| Encrypted or truncated application data | Packet metadata remains observable where headers are available. The model has no HTTP body, authenticated user, decrypted transaction or application signature as input. |
| Arbitrary collection boundaries | Original exporter history, service classifications and loss accounting are unavailable. Filling those columns with default values would manufacture evidence. The capture model has a separate feature contract. [Feature compatibility matrix](feature_compatibility.md) |
| Opening an exported subset in Wireshark | Wireshark assigns sequential frame numbers in the newly exported file. Use the original capture and the investigation's saved frame numbers for cross-reference. |
| File upload, reanalysis and CSV results | Capture identity and analysis/model identity are separate concepts. Repeated analyses of the same frames need separate provenance. Dataset CSV rows lack original packet IDs, addresses and frame evidence. |
| Data retention | Local captures can contain payloads, addresses and identifiers even when only metadata appears in the UI. Removing a capture or its records can remove the ability to verify original packets later. |

Before calling an alert confirmed, record the original capture identity, frame numbers, model version, the analyst's interpretation and the independent observation that supports it. If ordinary traffic only produces Normal predictions, the correct demonstration is to inspect an observed flow and report that outcome.
