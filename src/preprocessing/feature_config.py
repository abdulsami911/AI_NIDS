TARGET = "attack_cat"
DROP_COLUMNS = ["id", "label"]
CATEGORICAL_FEATURES = ["proto", "service", "state"]
RANDOM_STATE = 42
FULL = """dur proto service state spkts dpkts sbytes dbytes rate sttl dttl sload dload sloss
dloss sinpkt dinpkt sjit djit swin stcpb dtcpb dwin tcprtt synack ackdat smean dmean
trans_depth response_body_len ct_srv_src ct_state_ttl ct_dst_ltm ct_src_dport_ltm
ct_dst_sport_ltm ct_dst_src_ltm is_ftp_login ct_ftp_cmd ct_flw_http_mthd ct_src_ltm
ct_srv_dst is_sm_ips_ports""".split()
PCAP = ["dur", "proto", "spkts", "dpkts"]
CATEGORIES = "Analysis Backdoor DoS Exploits Fuzzers Generic Normal Reconnaissance Shellcode Worms".split()
SCHEMAS = {"full": FULL, "pcap": PCAP}
