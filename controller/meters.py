"""OpenFlow 1.3 meter helpers for the graduated (rate-limit) mitigation.

Every builder takes the datapath and uses its own `ofproto` and
`ofproto_parser`, so the messages can be checked offline with a fake datapath
that carries the real OS-Ken v1.3 modules. Nothing here sends a message.

A rate-limited source gets its own meter, numbered METER_ID_BASE plus the
last octet of its lab address (10.0.0.21 -> 1021), with one packets-per-second
drop band. The matching flow applies the meter before forwarding to the
victim's switch port, so Open vSwitch polices the flood in the datapath.
"""

from controller.lab import LAB_IP_TO_MAC, LAB_IPS, LAB_MAC_TO_PORT, VICTIM_IP, VICTIM_SWITCH_PORT

METER_ID_BASE = 1000


def meter_id_for(source):
    """Return the meter id reserved for one lab source address."""
    if source not in LAB_IPS:
        raise ValueError("source is not a lab host")
    return METER_ID_BASE + int(source.rsplit(".", 1)[1])


def source_for_meter_id(meter_id):
    """Map a meter id back to its lab source, or None for a foreign meter."""
    if not isinstance(meter_id, int):
        return None
    source = f"10.0.0.{meter_id - METER_ID_BASE}"
    return source if source in LAB_IPS and meter_id_for(source) == meter_id else None


def meter_mod_add(datapath, meter_id, rate_pps, burst, modify=False):
    """Build a packets-per-second meter with a single drop band.

    `modify=True` re-sends the band to an installed meter so a changed rate
    applies without deleting the flows that reference it.
    """
    ofp = datapath.ofproto
    parser = datapath.ofproto_parser
    flags = ofp.OFPMF_PKTPS | ofp.OFPMF_STATS | (ofp.OFPMF_BURST if burst else 0)
    return parser.OFPMeterMod(
        datapath,
        command=ofp.OFPMC_MODIFY if modify else ofp.OFPMC_ADD,
        flags=flags,
        meter_id=meter_id,
        bands=[parser.OFPMeterBandDrop(rate=int(rate_pps), burst_size=int(burst))],
    )


def meter_delete_all(datapath):
    """Remove every meter on the switch, used when it (re)connects."""
    ofp = datapath.ofproto
    return datapath.ofproto_parser.OFPMeterMod(
        datapath, command=ofp.OFPMC_DELETE, flags=0, meter_id=ofp.OFPM_ALL, bands=[])


def ratelimit_match_fields(source):
    """Service match of the drop rule plus the source's fixed port and MACs.

    Binding the limiter to the host identity means a frame forged with another
    port or MAC never reaches the forwarding action of the limiter flow.
    """
    from controller.forwarding import drop_match_fields  # avoid an import cycle

    mac = LAB_IP_TO_MAC[source]
    return {**drop_match_fields(source), "in_port": LAB_MAC_TO_PORT[mac],
            "eth_src": mac, "eth_dst": LAB_IP_TO_MAC[VICTIM_IP]}


def ratelimit_instructions(datapath, meter_id):
    """Meter first, then forward what the meter admits to the victim's port."""
    ofp = datapath.ofproto
    parser = datapath.ofproto_parser
    return [
        parser.OFPInstructionMeter(meter_id, ofp.OFPIT_METER),
        parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                     [parser.OFPActionOutput(VICTIM_SWITCH_PORT)]),
    ]


def meter_features_request(datapath):
    return datapath.ofproto_parser.OFPMeterFeaturesStatsRequest(datapath, 0)


def parse_meter_features(body, ofp):
    """Decide whether the switch can run a packets-per-second drop meter."""
    features = body[0] if body else None
    max_meter = int(getattr(features, "max_meter", 0) or 0)
    band_types = int(getattr(features, "band_types", 0) or 0)
    capabilities = int(getattr(features, "capabilities", 0) or 0)
    supported = (max_meter > 0 and bool(band_types & (1 << ofp.OFPMBT_DROP))
                 and bool(capabilities & ofp.OFPMF_PKTPS))
    return {"supported": supported, "max_meter": max_meter, "band_types": band_types,
            "capabilities": capabilities}


def meter_stats_request(datapath):
    ofp = datapath.ofproto
    return datapath.ofproto_parser.OFPMeterStatsRequest(datapath, 0, ofp.OFPM_ALL)
