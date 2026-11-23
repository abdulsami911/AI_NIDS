from decimal import Decimal
from src.traffic.pcap_engine import build_from_rows, transport_of


def packet(n,t,src,dst,sport,dport,proto='17',length=100):
    return {
        'frame.number':str(n),'frame.time_epoch':str(t),'frame.len':str(length),
        'ip.src':src,'ip.dst':dst,'ipv6.src':'','ipv6.dst':'',
        'ip.proto':proto,'ipv6.nxt':'',
        'tcp.srcport':sport if proto=='6' else '',
        'tcp.dstport':dport if proto=='6' else '',
        'udp.srcport':sport if proto=='17' else '',
        'udp.dstport':dport if proto=='17' else '',
        'icmp.type':'','icmpv6.type':'','tcp.flags.fin':'','tcp.flags.reset':'',
        '_ws.col.Protocol':'DNS' if proto=='17' else 'TCP',
    }


def test_bidirectional_flow_and_wireshark_frame_mapping():
    src,dst='10.0.0.1','10.0.0.2'
    rows=[packet(7,'100.000',src,dst,'4444','53',length=74),
          packet(15,'100.055',dst,src,'53','4444',length=99)]
    flows,packets,stats=build_from_rows(rows)
    assert stats['flow_count']==1
    assert [p['frame_number'] for p in packets]==[7,15]
    assert {p['flow_id'] for p in packets}=={flows[0]['flow_id']}
    assert [p['direction'] for p in packets]==['forward','backward']
    assert flows[0]['spkts']==1 and flows[0]['dpkts']==1
    assert flows[0]['dur']==0.055
    assert flows[0]['total_bytes']==173


def test_idle_timeout_causes_new_flow():
    rows=[packet(1,'0','10.0.0.1','10.0.0.2','1','53'),
          packet(2,'70','10.0.0.1','10.0.0.2','1','53')]
    flows,pkts,stats=build_from_rows(rows, idle_timeout=60)
    assert len(flows)==2
    assert pkts[0]['flow_id']!=pkts[1]['flow_id']


def test_icmp_error_quoted_ports_not_treated_as_udp():
    quoted=packet(3,'50','10.0.0.1','10.0.0.2','30000','53')
    quoted['ip.proto']='1'
    quoted['icmp.type']='3'
    quoted['_ws.col.Protocol']='ICMP'
    assert transport_of(quoted) is None
    flows,pkts,stats=build_from_rows([quoted])
    assert not flows and not pkts
    assert stats['unsupported_packets']==1


def test_ipv6_udp_not_lost():
    row=packet(2,'111','2001:db8::a','2001:db8::b','2233','443')
    row['ip.src']='';row['ip.dst']='';row['ip.proto']=''
    row['ipv6.src']='2001:db8::a';row['ipv6.dst']='2001:db8::b'
    row['ipv6.nxt']='17'
    flows,pkts,stats=build_from_rows([row])
    assert len(flows)==1 and flows[0]['proto']=='udp'


def test_time_interval_milliseconds():
    rows=[packet(1,'0','10.0.0.1','10.0.0.2','1','53'),
          packet(2,'0.1','10.0.0.1','10.0.0.2','1','53'),
          packet(3,'0.2','10.0.0.1','10.0.0.2','1','53')]
    flows,_,_=build_from_rows(rows)
    assert abs(flows[0]['sinpkt']-100)<1e-9


def test_ip_byte_accounting_and_reordered_timestamps():
    rows = [packet(1, "2", "10.0.0.1", "10.0.0.2", "1000", "53", length=74),
            packet(2, "1", "10.0.0.1", "10.0.0.2", "1000", "53", length=74),
            packet(3, "3", "10.0.0.2", "10.0.0.1", "53", "1000", length=99)]
    for r, length in zip(rows, ("60", "60", "85")):
        r["ip.len"] = length
    flows, _, stats = build_from_rows(rows)
    assert stats["flow_count"] == 1
    f = flows[0]
    assert (f["sbytes"], f["dbytes"], f["total_bytes"]) == (120, 85, 247)
    assert (f["dur"], f["sinpkt"], f["service"]) == (2, 1000, "dns")


def test_quic_with_embedded_tls_and_ipv6_lengths():
    row = packet(1, "1", "2001:db8::1", "2001:db8::2", "55000", "443")
    row.update({"ip.src": "", "ip.dst": "", "ip.proto": "", "ip.len": "",
                "ipv6.src": "2001:db8::1", "ipv6.dst": "2001:db8::2", "ipv6.plen": "80",
                "frame.protocols": "eth:ipv6:udp:quic:tls", "_ws.col.Protocol": "QUIC"})
    flows, _, _ = build_from_rows([row])
    assert (flows[0]["service"], flows[0]["sbytes"]) == ("quic", 120)


def test_response_first_uses_identified_requester():
    row = packet(1, "1", "10.0.0.2", "10.0.0.1", "53", "43000")
    row["dns.flags.response"] = "1"
    flows, packets, _ = build_from_rows([row])
    assert flows[0]["src_port"] == "43000" and flows[0]["spkts"] == 0
    assert packets[0]["direction"] == "backward"
