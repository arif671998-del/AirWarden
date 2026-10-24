"""Minimal, dependency-free pcap + radiotap + 802.11 codec.

Just enough of the format to WRITE synthetic test captures and READ them back
into schema.Frame objects. The files are standard libpcap/radiotap and open
cleanly in Wireshark, which makes them useful demo artefacts.

Scope: management frames (beacon, probe req/resp, deauth, disassoc) plus a
generic data-frame marker. This is NOT a full 802.11 stack; on real hardware
the live-capture path can use Scapy to produce the same Frame objects.

IMPORTANT: this module only reads and writes files. It never transmits a
frame and never touches a radio. All attack fixtures are offline test data.
"""
from __future__ import annotations

import struct
from typing import List, Optional, Tuple

from .schema import Frame, FrameType, Security

# pcap link-layer type: radiotap-prefixed 802.11
DLT_IEEE802_11_RADIOTAP = 127
PCAP_MAGIC = 0xA1B2C3D4

# 802.11 frame control subtypes (management)
_SUBTYPE_TO_TYPE = {
    0x08: FrameType.BEACON,
    0x04: FrameType.PROBE_REQ,
    0x05: FrameType.PROBE_RESP,
    0x0B: FrameType.AUTH,
    0x00: FrameType.ASSOC_REQ,
    0x01: FrameType.ASSOC_RESP,
    0x0C: FrameType.DEAUTH,
    0x0A: FrameType.DISASSOC,
}
_TYPE_TO_SUBTYPE = {v: k for k, v in _SUBTYPE_TO_TYPE.items()}


def mac_to_bytes(mac: str) -> bytes:
    return bytes(int(b, 16) for b in mac.split(":"))


def bytes_to_mac(b: bytes) -> str:
    return ":".join("%02x" % x for x in b)


def chan_to_freq(ch: int) -> int:
    if ch == 14:
        return 2484
    if 1 <= ch <= 13:
        return 2407 + ch * 5
    if 36 <= ch <= 165:          # 5 GHz
        return 5000 + ch * 5
    return 2412


def freq_to_chan(freq: int) -> Optional[int]:
    if freq == 2484:
        return 14
    if 2407 < freq <= 2472:
        return (freq - 2407) // 5
    if 5000 < freq < 5900:
        return (freq - 5000) // 5
    return None


# ---------------------------------------------------------------------------
# Radiotap (minimal: Flags, Channel, dBm antenna signal)
# ---------------------------------------------------------------------------

_PRESENT = (1 << 1) | (1 << 3) | (1 << 5)  # Flags | Channel | dBm signal


def _build_radiotap(channel: int, rssi: int) -> bytes:
    freq = chan_to_freq(channel)
    chan_flags = 0x0080 if channel <= 14 else 0x0100  # 2GHz vs 5GHz
    # layout (offsets from start): hdr[0:8], flags@8, pad@9, channel@10:14, sig@14
    body = bytearray()
    body += struct.pack("<B", 0x00)                    # flags
    body += struct.pack("<B", 0x00)                    # pad to align channel(2)
    body += struct.pack("<HH", freq, chan_flags)       # channel
    body += struct.pack("<b", rssi)                    # dBm antenna signal
    it_len = 8 + len(body)
    hdr = struct.pack("<BBHI", 0, 0, it_len, _PRESENT)
    return hdr + bytes(body)


def _parse_radiotap(buf: bytes) -> Tuple[int, Optional[int], Optional[int]]:
    """Return (header_len, channel, rssi). Best-effort for our own format."""
    if len(buf) < 8:
        return 0, None, None
    _, _, it_len, present = struct.unpack("<BBHI", buf[:8])
    channel = rssi = None
    off = 8
    try:
        if present & (1 << 1):   # Flags (1B, align 1)
            off += 1
        if present & (1 << 3):   # Channel (align 2)
            if off % 2:
                off += 1
            freq, _flags = struct.unpack("<HH", buf[off:off + 4])
            channel = freq_to_chan(freq)
            off += 4
        if present & (1 << 5):   # dBm signal (align 1)
            rssi = struct.unpack("<b", buf[off:off + 1])[0]
            off += 1
    except struct.error:
        pass
    return it_len, channel, rssi


# ---------------------------------------------------------------------------
# 802.11 management-frame body: tagged information elements
# ---------------------------------------------------------------------------

def _rsn_ie(wpa3: bool = False, pmf: bool = False) -> bytes:
    """Build an RSN IE (tag 48). AKM = SAE(8) when wpa3 else PSK(2)."""
    version = struct.pack("<H", 1)
    group = b"\x00\x0f\xac\x04"                 # CCMP
    pairwise = struct.pack("<H", 1) + b"\x00\x0f\xac\x04"
    akm_suite = b"\x00\x0f\xac\x08" if wpa3 else b"\x00\x0f\xac\x02"
    akm = struct.pack("<H", 1) + akm_suite
    # RSN capabilities: bit6 MFPR, bit7 MFPC
    caps = 0
    if pmf:
        caps |= (1 << 6) | (1 << 7)
    rsn_caps = struct.pack("<H", caps)
    body = version + group + pairwise + akm + rsn_caps
    return bytes([48, len(body)]) + body


def _wpa_ie() -> bytes:
    """Vendor-specific WPA1 IE (tag 221, OUI 00:50:f2 type 1)."""
    body = b"\x00\x50\xf2\x01" + struct.pack("<H", 1) + b"\x00\x50\xf2\x04"
    body += struct.pack("<H", 1) + b"\x00\x50\xf2\x02" + struct.pack("<H", 1) + b"\x00\x50\xf2\x02"
    return bytes([221, len(body)]) + body


def _mgmt_body(ssid: str, channel: int, security: Security, pmf: bool) -> bytes:
    privacy = 0x0010 if security != Security.OPEN else 0x0000
    cap = 0x0001 | privacy
    out = bytearray()
    out += struct.pack("<Q", 0)                 # timestamp
    out += struct.pack("<H", 100)               # beacon interval
    out += struct.pack("<H", cap)               # capability info
    ssid_b = ssid.encode()
    out += bytes([0, len(ssid_b)]) + ssid_b     # SSID (tag 0)
    out += bytes([1, 4, 0x82, 0x84, 0x8b, 0x96])  # supported rates (tag 1)
    out += bytes([3, 1, channel])               # DS param (tag 3)
    if security in (Security.WPA2, Security.WPA3):
        out += _rsn_ie(wpa3=(security == Security.WPA3), pmf=pmf)
    elif security == Security.WPA:
        out += _wpa_ie()
    return bytes(out)


def _parse_mgmt_body(body: bytes, is_beacon_like: bool) -> Tuple[Optional[str], Optional[int], Security, Optional[bool]]:
    ssid = None
    channel = None
    security = Security.UNKNOWN
    pmf = None
    privacy = False
    if not is_beacon_like:
        return ssid, channel, security, pmf
    if len(body) < 12:
        return ssid, channel, security, pmf
    cap = struct.unpack("<H", body[10:12])[0]
    privacy = bool(cap & 0x0010)
    i = 12
    has_rsn = has_wpa = wpa3 = False
    while i + 2 <= len(body):
        tag, ln = body[i], body[i + 1]
        val = body[i + 2:i + 2 + ln]
        if tag == 0:
            try:
                ssid = val.decode(errors="replace")
            except Exception:
                ssid = ""
        elif tag == 3 and ln >= 1:
            channel = val[0]
        elif tag == 48:
            has_rsn = True
            pmf, wpa3 = _parse_rsn_caps(val)
        elif tag == 221 and val[:4] == b"\x00\x50\xf2\x01":
            has_wpa = True
        i += 2 + ln
    if has_rsn:
        security = Security.WPA3 if wpa3 else Security.WPA2
    elif has_wpa:
        security = Security.WPA
    elif privacy:
        security = Security.WEP
    else:
        security = Security.OPEN
    return ssid, channel, security, pmf


def _parse_rsn_caps(val: bytes) -> Tuple[Optional[bool], bool]:
    """Return (pmf, is_wpa3). Walk the RSN IE to find AKM + capabilities."""
    try:
        off = 2 + 4                       # version + group cipher
        pw_count = struct.unpack("<H", val[off:off + 2])[0]
        off += 2 + 4 * pw_count
        akm_count = struct.unpack("<H", val[off:off + 2])[0]
        akm_suites = val[off + 2:off + 2 + 4 * akm_count]
        off += 2 + 4 * akm_count
        wpa3 = any(akm_suites[j:j + 4] == b"\x00\x0f\xac\x08"
                   for j in range(0, len(akm_suites), 4))
        pmf = None
        if off + 2 <= len(val):
            caps = struct.unpack("<H", val[off:off + 2])[0]
            pmf = bool(caps & (1 << 7))
        return pmf, wpa3
    except (struct.error, IndexError):
        return None, False


# ---------------------------------------------------------------------------
# Frame encode / decode
# ---------------------------------------------------------------------------

def encode_frame(f: Frame) -> bytes:
    subtype = _TYPE_TO_SUBTYPE.get(f.ftype, 0x08)
    fc0 = (subtype << 4) | 0x00          # type=00 management
    mac = struct.pack("<BB", fc0, 0x00)
    mac += struct.pack("<H", 0)          # duration
    mac += mac_to_bytes(f.addr1 or "ff:ff:ff:ff:ff:ff")
    mac += mac_to_bytes(f.addr2 or "00:00:00:00:00:00")
    mac += mac_to_bytes(f.addr3 or "00:00:00:00:00:00")
    mac += struct.pack("<H", ((f.seq or 0) & 0x0FFF) << 4)  # seq ctrl (frag 0)
    if f.ftype in (FrameType.DEAUTH, FrameType.DISASSOC):
        body = struct.pack("<H", f.reason or 7)
    elif f.ftype in (FrameType.BEACON, FrameType.PROBE_RESP):
        body = _mgmt_body(f.ssid or "", f.channel or 1,
                          f.security if f.security != Security.UNKNOWN else Security.OPEN,
                          bool(f.pmf))
    elif f.ftype == FrameType.PROBE_REQ:
        ssid_b = (f.ssid or "").encode()
        body = bytes([0, len(ssid_b)]) + ssid_b
    else:
        body = b""
    return mac + body


def decode_frame(ts: float, raw: bytes, channel: Optional[int], rssi: Optional[int]) -> Optional[Frame]:
    if len(raw) < 24:
        return None
    fc0 = raw[0]
    ftype_bits = (fc0 >> 2) & 0x03
    subtype = (fc0 >> 4) & 0x0F
    if ftype_bits == 2:                   # data frame
        f = Frame(ts=ts, ftype=FrameType.DATA)
        f.addr1 = bytes_to_mac(raw[4:10])
        f.addr2 = bytes_to_mac(raw[10:16])
        f.addr3 = bytes_to_mac(raw[16:22])
        f.channel, f.rssi = channel, rssi
        return f
    if ftype_bits != 0:                   # only mgmt + data handled
        return Frame(ts=ts, ftype=FrameType.OTHER, channel=channel, rssi=rssi)
    ftype = _SUBTYPE_TO_TYPE.get(subtype, FrameType.OTHER)
    f = Frame(ts=ts, ftype=ftype, channel=channel, rssi=rssi)
    f.addr1 = bytes_to_mac(raw[4:10])
    f.addr2 = bytes_to_mac(raw[10:16])
    f.addr3 = bytes_to_mac(raw[16:22])
    f.seq = (struct.unpack("<H", raw[22:24])[0] >> 4) & 0x0FFF
    body = raw[24:]
    if ftype in (FrameType.DEAUTH, FrameType.DISASSOC):
        if len(body) >= 2:
            f.reason = struct.unpack("<H", body[:2])[0]
    elif ftype in (FrameType.BEACON, FrameType.PROBE_RESP):
        ssid, ch, sec, pmf = _parse_mgmt_body(body, True)
        f.ssid, f.security, f.pmf = ssid, sec, pmf
        if ch:
            f.channel = ch
    elif ftype == FrameType.PROBE_REQ:
        if len(body) >= 2 and body[0] == 0:
            ln = body[1]
            f.ssid = body[2:2 + ln].decode(errors="replace")
    return f


# ---------------------------------------------------------------------------
# File I/O
# ---------------------------------------------------------------------------

def write_pcap(path: str, frames: List[Frame]) -> None:
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", PCAP_MAGIC, 2, 4, 0, 0, 65535,
                             DLT_IEEE802_11_RADIOTAP))
        for f in frames:
            rt = _build_radiotap(f.channel or 1, f.rssi if f.rssi is not None else -50)
            raw = rt + encode_frame(f)
            sec = int(f.ts)
            usec = int((f.ts - sec) * 1_000_000)
            fh.write(struct.pack("<IIII", sec, usec, len(raw), len(raw)))
            fh.write(raw)


def read_pcap(path: str) -> List[Frame]:
    frames: List[Frame] = []
    with open(path, "rb") as fh:
        gh = fh.read(24)
        if len(gh) < 24:
            return frames
        magic = struct.unpack("<I", gh[:4])[0]
        endian = "<" if magic == PCAP_MAGIC else ">"
        linktype = struct.unpack(endian + "I", gh[20:24])[0]
        while True:
            ph = fh.read(16)
            if len(ph) < 16:
                break
            sec, usec, caplen, _ = struct.unpack(endian + "IIII", ph)
            raw = fh.read(caplen)
            ts = sec + usec / 1_000_000
            if linktype == DLT_IEEE802_11_RADIOTAP:
                rt_len, ch, rssi = _parse_radiotap(raw)
                dot11 = raw[rt_len:]
            else:
                ch = rssi = None
                dot11 = raw
            fr = decode_frame(ts, dot11, ch, rssi)
            if fr:
                frames.append(fr)
    return frames
