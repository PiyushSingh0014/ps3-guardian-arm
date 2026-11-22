"""One network connection (a flow), in the same shape whatever produced it.

Live traffic and pcap files are read with NFStream; labelled public datasets come as
CSV files from CICFlowMeter (CIC-IDS2017). Both are turned into a FlowRec, so the
detectors in rules.py work the same on live traffic and on test data.

A flow is one conversation between two addresses and ports. `src` is the side that
sent the first packet (the one that started the connection).
"""
import csv
import ipaddress
from dataclasses import dataclass
from datetime import datetime
from typing import Iterator, Optional

TCP, UDP, ICMP = 6, 17, 1


@dataclass
class FlowRec:
    start_ms: int          # first packet, milliseconds since 1970
    end_ms: int            # last packet
    src: str               # who started it
    dst: str
    sport: int
    dport: int
    proto: int             # 6 TCP, 17 UDP, 1 ICMP
    pkts_out: int          # packets src -> dst
    pkts_in: int           # packets dst -> src
    bytes_out: int         # bytes src -> dst
    bytes_in: int
    syn_out: int = 0       # SYN packets src -> dst
    rst_in: int = 0        # RST packets dst -> src (the port is closed)
    app: str = ""          # application guessed by nDPI (live only), e.g. "DNS", "TLS"
    server_name: str = ""  # DNS name asked, TLS server name or HTTP host (live only)
    src_mac: str = ""
    label: str = ""        # ground truth, for test data only
    # False for CIC-IDS2017 CSV rows: they carry no server names, and their SYN counts are 0
    # even for port scans (a CICFlowMeter fault), so they cannot tell a new connection from
    # the rest of an open one.
    from_capture: bool = True

    @property
    def duration_ms(self):
        return max(0, self.end_ms - self.start_ms)

    @property
    def answered(self):
        """Did the other side answer with anything but a refusal?"""
        return self.pkts_in > self.rst_in

    @property
    def failed(self):
        """A connection attempt that went nowhere: no answer, refused, or a bare handshake.

        Up to 6 bytes per packet count as nothing: CICFlowMeter counts Ethernet padding of
        empty packets as data (Engelen et al., 2021).
        """
        empty = self.bytes_in <= 6 * self.pkts_in
        return self.pkts_in == 0 or self.rst_in > 0 or (self.proto == TCP and self.pkts_out <= 2 and empty)

    @property
    def looks_like_reply(self):
        """From a service port to a client's temporary port: the tail of a server's answer
        cut off as a flow of its own, not a new connection."""
        return 0 < self.sport < 1024 and self.dport >= 1024

    @property
    def new_connection(self):
        """Did this flow open a connection (a TCP handshake), rather than carry on one that was
        already open? The flow meter cuts a long connection into a new flow after 10 s of
        silence, so a keep-alive every 45 s shows up as a flow every 45 s, without a SYN."""
        return self.proto != TCP or not self.from_capture or self.syn_out > 0

    @property
    def is_dns(self):
        return self.dport == 53 or self.app.startswith("DNS")


def is_private(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_private or a.is_link_local or a.is_loopback or a.is_multicast


def is_device(ip: str) -> bool:
    """An address a device on the Wi-Fi uses for its own traffic: private, and not 0.0.0.0 (a
    device still asking the hotspot for an address), link-local, loopback, multicast or broadcast."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_private and not (a.is_unspecified or a.is_link_local or a.is_loopback or a.is_multicast
                                 or a.is_reserved)


def from_nfstream(f) -> FlowRec:
    """An NFStream NFlow (accounting_mode=3: payload bytes, like CICFlowMeter) -> FlowRec."""
    return FlowRec(
        start_ms=int(f.bidirectional_first_seen_ms), end_ms=int(f.bidirectional_last_seen_ms),
        src=f.src_ip, dst=f.dst_ip, sport=int(f.src_port or 0), dport=int(f.dst_port or 0), proto=int(f.protocol),
        pkts_out=int(f.src2dst_packets), pkts_in=int(f.dst2src_packets),
        bytes_out=int(f.src2dst_bytes), bytes_in=int(f.dst2src_bytes),
        syn_out=int(getattr(f, "src2dst_syn_packets", 0) or 0), rst_in=int(getattr(f, "dst2src_rst_packets", 0) or 0),
        app=str(f.application_name or ""), server_name=str(f.requested_server_name or "").lower().rstrip("."),
        src_mac=str(f.src_mac or ""))


def streamer(source, idle_timeout=10, active_timeout=60, bpf_filter=None):
    """NFStream flows from a network interface (live) or a pcap file.

    Short timeouts: a flow is reported when it has been quiet for `idle_timeout` seconds,
    so alerts come within seconds instead of the default two minutes.
    """
    from nfstream import NFStreamer      # imported here: tests and CSV evaluation do not need it
    return NFStreamer(source=source, idle_timeout=idle_timeout, active_timeout=active_timeout,
                      accounting_mode=3, statistical_analysis=True, bpf_filter=bpf_filter,
                      n_dissections=20)


def read_flows(source, **kw) -> Iterator[FlowRec]:
    for f in streamer(source, **kw):
        yield from_nfstream(f)


# --- CIC-IDS2017 (CICFlowMeter CSV, "GeneratedLabelledFlows") ---------------------
_CIC_TIME_FORMATS = ("%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M", "%d/%m/%Y %I:%M:%S %p", "%d/%m/%Y %I:%M")


def _cic_time(text, pm_hint=False):
    text = text.strip()
    for fmt in _CIC_TIME_FORMATS:
        try:
            t = datetime.strptime(text, fmt)
            break
        except ValueError:
            continue
    else:
        return None
    # CIC-IDS2017 writes afternoon times without AM/PM ("3:30" is 15:30): the capture ran
    # 8:00-17:00, so hours 1-7 are afternoon.
    if t.hour < 8:
        t = t.replace(hour=t.hour + 12)
    return int(t.timestamp() * 1000)


def _num(row, *names, default=0.0):
    for n in names:
        v = row.get(n)
        if v not in (None, ""):
            try:
                return float(v)
            except ValueError:
                return default
    return default


def from_cic_row(row) -> Optional[FlowRec]:
    """One row of a CIC-IDS2017 GeneratedLabelledFlows CSV -> FlowRec (None if unusable)."""
    row = {k.strip(): v for k, v in row.items() if k}
    start = _cic_time(row.get("Timestamp", ""))
    if start is None or not row.get("Source IP"):
        return None
    dur_ms = int(_num(row, "Flow Duration") / 1000)            # microseconds there
    proto = int(_num(row, "Protocol"))
    return FlowRec(
        start_ms=start, end_ms=start + max(0, dur_ms), src=row["Source IP"].strip(), dst=row["Destination IP"].strip(),
        sport=int(_num(row, "Source Port")), dport=int(_num(row, "Destination Port")), proto=proto,
        pkts_out=int(_num(row, "Total Fwd Packets")), pkts_in=int(_num(row, "Total Backward Packets")),
        bytes_out=int(_num(row, "Total Length of Fwd Packets")), bytes_in=int(_num(row, "Total Length of Bwd Packets")),
        syn_out=int(_num(row, "SYN Flag Count")), rst_in=int(_num(row, "RST Flag Count")),
        label=(row.get("Label") or "").strip(), from_capture=False)


def read_cic_csv(path) -> Iterator[FlowRec]:
    with open(path, encoding="utf-8", errors="replace", newline="") as f:
        for row in csv.DictReader(f):
            rec = from_cic_row(row)
            if rec:
                yield rec
