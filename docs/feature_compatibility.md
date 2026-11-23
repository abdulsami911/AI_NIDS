# UNSW-NB15 input compatibility

This study describes the earlier four-feature registry model. The current upload dashboard uses the [capture suite and feature definitions](FEATURE_AND_ACCURACY_LIMITATIONS.md).

The full benchmark uses the 42 predictors in the official split files. The capture model uses four columns, in order, `dur`, `proto`, `spkts`, `dpkts`. A capture supplies the observed duration, transport protocol and two directional frame counts. Its byte totals, endpoint addresses, ports and TCP flags remain useful investigation evidence.

The local training CSV has 175,341 rows and the testing CSV has 82,332. Both have 45 columns including the row ID, multiclass target and binary target. The source dataset used Argus, Bro and additional feature-generation algorithms. Its feature dictionary covers the original records, while the published splits rename some fields, omit others and add `rate`. The split files omit endpoint addresses and absolute times, which prevents joining their rows to arbitrary captured flows. [UNSW dataset and publication details](https://research.unsw.edu.au/projects/unsw-nb15-dataset) · [Local feature dictionary](../datasets/unsw_nb15/NUSW-NB15_features.csv)

## Reading the matrix

**Included** means the measured quantity has the documented units and meaning for the chosen observation window and direction. **Conditional** means particular captures or a known exporter configuration could supply it reliably. **Unavailable** means the inputs or conventions required for general reproduction are missing here. **Direct** means the raw quantity can be computed for a limited protocol domain, even though this model omits it. A feature marked *withheld* never enters the capture model. Numeric “int” denotes an integer quantity in the dataset, including binary flags.

| Split column | Type | Training meaning | Required evidence and candidate extraction | Reliability, limitations and validation status |
|---|---|---|---|---|
| `dur` | float, seconds | Elapsed time of the record | Subtract earliest member frame timestamp from latest | Included. A singleton has zero duration. A capture boundary changes the observed interval. Frame-pair check below. |
| `proto` | category | Network transaction protocol | Read decoded protocol headers and use the training spelling, e.g. `tcp` or `udp` | Included for supported traffic. Ports and top-level application names do not define this field. Frame-pair check below. |
| `service` | category | Application service recognized by the exporter | Reconstruct application transactions and map recognized services to the original vocabulary | Conditional, withheld. A destination port alone cannot establish service, especially for encrypted and nonstandard-port traffic. |
| `state` | category | Protocol-specific Argus transaction state | Track the bidirectional protocol state and reproduce the original exporter mapping | Conditional, withheld. Observed TCP SYN/FIN flags alone cannot reconstruct all states. |
| `spkts` | int, packets | Frames from source to destination within the record | Count each member frame assigned to the originating side once | Included. Orientation and transaction boundaries affect the value. Retransmissions are observations. Frame-pair check below. |
| `dpkts` | int, packets | Frames from destination to source within the record | Count member frames assigned to the opposite side | Included. Zero means no reverse frames **observed**. Frame-pair check below. |
| `sbytes` | int, bytes | Source-side transaction octets | Sum original exporter byte lengths in the forward direction | Conditional, withheld. Link-layer headers, padding and selection of accounting layer can change sums. |
| `dbytes` | int, bytes | Reverse transaction octets | Sum original exporter byte lengths in the reverse direction | Conditional, withheld. A TShark wire-length sum has a distinct definition. |
| `rate` | float, per second | Record packet rate in the split CSV | Establish counted intervals and divide by duration under the exporter's zero-duration rule | Conditional, withheld. See empirical split check below. |
| `sttl` | int, hops | Forward IP time-to-live value | Read source-side IP TTL and reproduce the exporter's choice when it varies | Conditional, withheld. Missing directions, IPv6 hop limits and aggregation conventions affect parity. |
| `dttl` | int, hops | Reverse IP time-to-live value | Read the opposite side's IP TTL and establish its aggregation rule | Conditional, withheld. Reverse traffic may be absent. |
| `sload` | float, bit/s | Source-side traffic load | Combine directional octets with exporter-specific observation intervals | Conditional, withheld. The byte boundary and timing denominator need independent validation. |
| `dload` | float, bit/s | Destination-side traffic load | Combine reverse octets with reverse timing under the same rules | Conditional, withheld. Empty directions and zero duration need defined conventions. |
| `sloss` | int, packets | Forward retransmitted or dropped packets | Interpret sequence numbers, ACKs and sequence gaps using exporter rules | Unavailable in general, withheld. Sensor loss and remote packet loss can produce similar observations. |
| `dloss` | int, packets | Reverse retransmitted or dropped packets | Reconstruct receiver-side loss using reverse sequence and ACK histories | Unavailable in general, withheld. A single asymmetric vantage point can miss the evidence. |
| `sinpkt` | float, ms | Source interpacket interval | Collect forward timestamps and reproduce the directional interval statistic | Conditional, withheld. Requires exact aggregation, rounding and singleton conventions. |
| `dinpkt` | float, ms | Destination interpacket interval | Collect reverse timestamps and apply the directional interval statistic | Conditional, withheld. A missing direction has no measured interval. |
| `sjit` | float, ms | Source arrival jitter | Use the original jitter estimator on forward packet times | Conditional, withheld. Multiple jitter estimators differ on the same timestamps. |
| `djit` | float, ms | Destination arrival jitter | Use the original jitter estimator on reverse packet times | Conditional, withheld. Sparse flows may have too few observations. |
| `swin` | int | Source advertised TCP window | Track raw advertisements, negotiated scale and exporter's sample selection | Conditional, withheld. Midstream capture can miss scale negotiation. |
| `stcpb` | int | Source TCP base sequence number | Obtain forward initial raw TCP sequence from opening handshake | Conditional, withheld. Relative display sequence numbers or a midstream segment give a different quantity. |
| `dtcpb` | int | Destination TCP base sequence number | Obtain the peer's initial raw sequence from its handshake | Conditional, withheld. Captures can start after the responder has sent data. |
| `dwin` | int | Destination advertised TCP window | Read reverse TCP window advertisements and reproduce sample/scale convention | Conditional, withheld. The reverse handshake may be absent. |
| `tcprtt` | float, seconds | TCP handshake time comprising `synack` plus `ackdat` | Match all handshake legs and add the two intervals | Conditional, withheld. An ACK RTT for an arbitrary segment measures something else. |
| `synack` | float, seconds | Interval from initial SYN to its SYN-ACK | Pair forward SYN with the responding SYN-ACK and subtract arrival times | Conditional, withheld. Missing or retransmitted SYNs make the selected pair ambiguous. |
| `ackdat` | float, seconds | Interval from SYN-ACK to the final handshake ACK | Match the reverse SYN-ACK with its acknowledging sequence | Conditional, withheld. Incomplete handshakes cannot yield the interval. |
| `smean` | int, bytes | Mean forward packet size (`smeansz`) | Match the source transaction-byte accounting, divide by count and establish rounding | Conditional, withheld. Using mean wire length would inherit the `sbytes` mismatch. |
| `dmean` | int, bytes | Mean reverse packet size (`dmeansz`) | Match the reverse byte definition, count and rounding | Conditional, withheld. Reverse count may be zero. |
| `trans_depth` | int | HTTP pipelined request/response depth | Reassemble plaintext application messages and track transaction depth | Unavailable for general encrypted or partial sessions, withheld. |
| `response_body_len` | int, bytes | Uncompressed HTTP response-body size (`res_bdy_len`) | Decode complete response bodies including transfer/content encoding | Unavailable for general encrypted or truncated captures, withheld. TCP bytes include other data. |
| `ct_srv_src` | int, flows | Recent connections sharing application service and source | Maintain the exporter's service labels and ordered 100-connection history | Unavailable from an isolated observation window, withheld. |
| `ct_state_ttl` | int | Count for connection state and directional TTL range | Reproduce state assignment, TTL bins and counting context | Unavailable with the present state and TTL conventions, withheld. |
| `ct_dst_ltm` | int, flows | Recent connections to the same destination | Count destination matches in the exporter's 100-connection sequence | Unavailable without ordered history preceding capture, withheld. |
| `ct_src_dport_ltm` | int, flows | Recent connections sharing source and destination port | Count matching origin/port pairs in that same history | Unavailable without preceding connections and orientation parity, withheld. |
| `ct_dst_sport_ltm` | int, flows | Recent connections sharing destination and source port | Count matching destination/origin-port pairs in order | Unavailable without preceding connections and orientation parity, withheld. |
| `ct_dst_src_ltm` | int, flows | Recent connections sharing the source/destination pair | Count oriented address-pair matches in ordered history | Unavailable without preceding connections and exporter direction, withheld. |
| `is_ftp_login` | documented binary, stored int | FTP session accessed using credentials | Reassemble FTP control conversation and apply original login criteria | Unavailable for general captures, withheld. Local training values include 2 and 4, beyond the dictionary's binary description. |
| `ct_ftp_cmd` | int | Count associated with FTP command-bearing flows | Decode FTP control messages and match exporter transaction aggregation | Unavailable for encrypted or partial sessions, withheld. |
| `ct_flw_http_mthd` | int, flows | Count of flows with a recognized HTTP method | Reassemble HTTP requests and reproduce original flow counting scope | Unavailable without application visibility and matching history, withheld. |
| `ct_src_ltm` | int, flows | Recent connections from the same source | Count oriented source matches in ordered 100-connection history | Unavailable without preceding records, withheld. |
| `ct_srv_dst` | int, flows | Recent connections sharing application service and destination | Group exporter-recognized services and destination in that history | Unavailable without service semantics and preceding history, withheld. |
| `is_sm_ips_ports` | binary int | Source and destination IP match and both ports match | Compare normalized IPs and transport ports for equality | Direct for fully parsed TCP/UDP. Withheld to avoid importing unverified portless conventions. |

## Verification and remaining uncertainty

**Independent packet check.** In the existing `firsttime.pcapng`, TShark assigns frames 7 and 15 to UDP stream 0. Comparing the two records gives swapped address/port pairs and a timestamp difference of 0.055503368 seconds. The application extractor and flow builder returned those same two frame numbers and the expected feature vector `[0.055503368, "udp", 1, 1]`. Frame numbers identify records within this capture only. Reproduce the measurement locally with the following command. SHA-256 of the capture is `a7cef8c5211c11c404b08bc5afcfd9903d0d6d17d6d656e3a3dc550c2f435177`. [Wireshark frame field reference](https://www.wireshark.org/docs/dfref/f/frame.html)

```bash
tshark -n -r datasets/pcap_samples/firsttime.pcapng -Y 'udp.stream == 0' \
  -T fields -e frame.number -e frame.time_epoch -e ip.src -e udp.srcport \
  -e ip.dst -e udp.dstport -e ipv6.src -e ipv6.dst
```

**Observed bounds.** Both split files have maximum duration 59.999989 seconds and minimum source count 1. The training split includes 2,657 records with zero duration. On positive-duration training records `(spkts + dpkts - 1) / dur` agrees with `rate` within an absolute tolerance of `0.001 × (1 + abs(rate))` throughout. The same check agrees on 98.46% of positive-duration test records. A dashboard rate defined as packets divided by duration cannot substitute for the split's rate feature.

**Protocol coverage.** All 15 training rows with protocol spelled `icmp` are Normal. The test split contains no such rows. Neither split contains an ICMPv6 category under `icmpv6` or `ipv6-icmp`. IPv4 echo can receive predictions with this severe coverage limitation. IPv6 echo remains available as evidence only. The parser omits fragmented, tunneled and non-echo ICMP traffic. Echo identifiers help separate conversations. Interpreting prediction quality for ICMP, or treating a protocol spelling absent from training as evidence of an attack, has no empirical support in this evaluation.

**Session boundaries.** The first observed sender gives a reproducible orientation for captures that begin midstream, with a SYN-ACK identifying the responder when seen first. Echo request/reply types identify the requesting side. A reverse-only trace or dropped opening packet can reverse an inferred role or yield zero observed origin packets. Timeouts, TCP reuse and the capture start/end delimit records. Argus supports protocol-specific keys including a DNS transaction identifier. Repeated queries on the same socket may therefore be divided differently. Matching the four quantities and their units does not establish row-for-row equivalence to Argus records. That requires ground-truth paired source captures and matching exporter configuration. [Argus sensor documentation](https://openargus.org/argus-ids)
