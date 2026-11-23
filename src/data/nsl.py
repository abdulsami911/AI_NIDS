"""NSL-KDD full TXT format in the KDD Cup feature order."""
import pandas as pd
from src.preprocessing.preprocess import ROOT

COLUMNS = """duration protocol_type service flag src_bytes dst_bytes land wrong_fragment
urgent hot num_failed_logins logged_in num_compromised root_shell su_attempted num_root
num_file_creations num_shells num_access_files num_outbound_cmds is_host_login
is_guest_login count srv_count serror_rate srv_serror_rate rerror_rate srv_rerror_rate
same_srv_rate diff_srv_rate srv_diff_host_rate dst_host_count dst_host_srv_count
dst_host_same_srv_rate dst_host_diff_srv_rate dst_host_same_src_port_rate
dst_host_srv_diff_host_rate dst_host_serror_rate dst_host_srv_serror_rate
dst_host_rerror_rate dst_host_srv_rerror_rate""".split()
CATS = ["protocol_type", "service", "flag"]
GROUPS = {
    "Normal": "normal",
    "DoS": "apache2 back land mailbomb neptune pod processtable smurf teardrop udpstorm",
    "Probe": "ipsweep mscan nmap portsweep saint satan",
    "R2L": "ftp_write guess_passwd httptunnel imap multihop named phf sendmail snmpgetattack snmpguess spy warezclient warezmaster xlock xsnoop",
    "U2R": "buffer_overflow loadmodule perl ps rootkit sqlattack xterm",
}
LABELS = {attack: family for family, attacks in GROUPS.items() for attack in attacks.split()}


def read_nsl(path):
    frame = pd.read_csv(path, header=None)
    if frame.shape[1] != 43 or frame.isna().any().any():
        raise ValueError("Expected 41 NSL-KDD fields, attack name and difficulty")
    frame.columns = COLUMNS + ["attack", "difficulty"]
    labels = frame.attack.str.strip().str.rstrip(".").map(LABELS)
    if labels.isna().any():
        raise ValueError("Unrecognized NSL-KDD attack label")
    for col in set(COLUMNS) - set(CATS):
        frame[col] = pd.to_numeric(frame[col], errors="raise")
    return frame[COLUMNS], labels


def load_nsl():
    folder = ROOT / "datasets/nsl_kdd"
    train, y = read_nsl(folder / "KDDTrain+.txt")
    test, yt = read_nsl(folder / "KDDTest+.txt")
    return train, test, y, yt
