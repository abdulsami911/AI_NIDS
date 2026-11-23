# Capture features and interpretation

The dashboard started by `run_nids.py` and the direct PCAP command use the same TShark extractor and fitted pipeline. Training uses the official UNSW-NB15 split CSVs. Deployment approximates selected exporter measurements from observed frames. Equality with the original UNSW Argus/Bro feature-generation pipeline remains unverified.

| Input | Measurement at inference |
|---|---|
| `proto` | Decoded TCP or UDP over a single IPv4 or IPv6 layer. Fragmented IP and encapsulated traffic are skipped. |
| `dur` | Latest minus earliest observed timestamp in seconds. |
| `spkts`, `dpkts` | Frame counts in each direction. TCP SYN-ACK or a DNS response at flow creation identifies the responder. Otherwise, the first sender defines the forward direction. |
| `sinpkt`, `dinpkt` | Time span within a direction divided by its number of interpacket intervals, in milliseconds. Zero or one frame in a direction yields zero. |
| `is_sm_ips_ports` | Equality of both endpoint addresses and both transport ports. |
| `service` | Recognized application dissector mapped into the training vocabulary, with a dash for unidentified service. QUIC has its own observed identity and falls outside service-aware UNSW training coverage. |
| `sbytes`, `dbytes` | Summed network-layer octets per direction using the IPv4 total length or IPv6 payload length plus the 40-byte base header. The separate investigation field `total_bytes` counts on-wire frame lengths. |

A flow is scoped by capture interface, VLAN identifier, transport stream and bidirectional endpoint pair. The default idle and active timeouts are both 60 seconds. TCP close/reset and capture boundaries can split records. Partial capture, offload, NAT, reused tuples and application dissection can all change measured inputs. The engine retains each supported frame's original number. It excludes other transports and cannot recover missing packets.

The suite stores observed training coverage for each fitted model before resampling. Count buckets are zero, one, two to three, four to seven and successively wider powers-of-two ranges. A flow requires a training observation with matching transport, service (for service-aware models) and both count buckets to receive a category. Passing the check establishes basic support for the input. It does not establish the reliability of a prediction. The classifier can still miss attacks or misidentify normal traffic.

The primary benchmark measures UNSW categories. NSL-KDD is an independently fitted binary benchmark. The external captures have publisher-assigned file labels. An external malware family name cannot validate a particular UNSW attack category. The sample Wireshark capture in this workspace has no supplied attack annotations.

The earlier four-input registry benchmark and its separate extractor are documented in [the compatibility study](feature_compatibility.md). The seven-feature and eight-feature experiments remain in the project for historical comparison.
