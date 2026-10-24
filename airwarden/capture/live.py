"""Live monitor-mode capture via Scapy (optional backend).

Runs on the real sensor (Raspberry Pi or laptop) with a monitor-mode adapter.
Converts Scapy Dot11 frames into the same schema.Frame objects the rest of the
pipeline consumes, so detection/agent/response code is identical whether frames
come from the air or from a recorded pcap.

Scapy is imported lazily: this module only needs it when you actually start a
live capture, so the rest of AirWarden runs without it installed.

Monitor mode (Linux), e.g.:
    sudo airmon-ng start wlan0            # -> wlan0mon
    sudo python3 -m airwarden.capture.live wlan0mon
"""
from __future__ import annotations

from typing import Callable, Optional

from ..schema import Frame, FrameType, Security

_SUBTYPE = {8: FrameType.BEACON, 4: FrameType.PROBE_REQ, 5: FrameType.PROBE_RESP,
            12: FrameType.DEAUTH, 10: FrameType.DISASSOC, 11: FrameType.AUTH}


def _to_frame(pkt) -> Optional[Frame]:
    from scapy.layers.dot11 import (Dot11, Dot11Beacon, Dot11ProbeResp,
                                    Dot11Deauth, Dot11Elt, RadioTap)
    if not pkt.haslayer(Dot11):
        return None
    d = pkt.getlayer(Dot11)
    if d.type != 0:                      # management frames only here
        return None
    ftype = _SUBTYPE.get(d.subtype, FrameType.OTHER)
    f = Frame(ts=float(pkt.time), ftype=ftype,
              addr1=(d.addr1 or ""), addr2=(d.addr2 or ""), addr3=(d.addr3 or ""))
    try:
        if d.SC is not None:
            f.seq = (int(d.SC) >> 4) & 0x0FFF
    except Exception:
        pass
    if pkt.haslayer(RadioTap):
        rt = pkt.getlayer(RadioTap)
        f.rssi = getattr(rt, "dBm_AntSignal", None)
    if pkt.haslayer(Dot11Deauth):
        f.reason = int(pkt.getlayer(Dot11Deauth).reason)
    if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
        f.ssid, f.channel, f.security = _parse_elts(pkt)
    return f


def _parse_elts(pkt):
    from scapy.layers.dot11 import Dot11Elt
    ssid = None
    channel = None
    security = Security.OPEN
    has_rsn = has_wpa = False
    el = pkt.getlayer(Dot11Elt)
    while isinstance(el, Dot11Elt):
        if el.ID == 0:
            ssid = el.info.decode(errors="replace")
        elif el.ID == 3 and el.info:
            channel = el.info[0]
        elif el.ID == 48:
            has_rsn = True
        elif el.ID == 221 and el.info[:4] == b"\x00\x50\xf2\x01":
            has_wpa = True
        el = el.payload.getlayer(Dot11Elt)
    if has_rsn:
        security = Security.WPA2
    elif has_wpa:
        security = Security.WPA
    # capability privacy bit -> WEP if set without RSN/WPA
    try:
        if security == Security.OPEN and (pkt.cap & 0x10):
            security = Security.WEP
    except Exception:
        pass
    return ssid, channel, security


def sniff_live(iface: str, on_frame: Callable[[Frame], None], count: int = 0):
    """Capture from a monitor-mode interface, calling on_frame per frame."""
    from scapy.sendrecv import sniff

    def _cb(pkt):
        fr = _to_frame(pkt)
        if fr:
            on_frame(fr)

    sniff(iface=iface, prn=_cb, store=False, count=count)


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("usage: python3 -m airwarden.capture.live <monitor-iface>")
        raise SystemExit(1)
    sniff_live(sys.argv[1], lambda f: print(f.to_dict()))
