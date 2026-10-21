-- FlowGuard Lab Protocol dissector for Wireshark / tshark.
--
-- Decodes the UDP payloads used by the FlowGuard lab:
--   * FGPB binary probe/flood header (traffic/probe_protocol.py), with CRC32 check
--   * legacy text probes      "ddos-probe:<seq>:<ns>"
--   * Mininet flood payloads  "FLOWGUARD-LAB-ONLY:XXXX..."
--   * native lab payloads     "flowguard:<source>:<phase>:<seq>:<ns>...."
--
-- Usage (one-off):
--   wireshark -X lua_script:wireshark/flowguard.lua capture.pcapng
--   tshark -X lua_script:wireshark/flowguard.lua -r capture.pcapng -Y flowguard
-- Install permanently: copy this file to ~/.local/lib/wireshark/plugins/
-- (Windows: %APPDATA%\Wireshark\plugins\) and restart Wireshark.
--
-- A UDP heuristic finds the payloads on any port. If another dissector owns the
-- port first, use Analyze > Decode As... > UDP port > FLOWGUARD, or enable the
-- UDP preference "Try heuristic sub-dissectors first".
-- Filters: flowguard, flowguard.seq, flowguard.kind == "probe", flowguard.crc_ok == 0.
-- Works with Lua 5.2 (Wireshark 4.2, bit32) and Lua 5.3/5.4 (Wireshark >= 4.4).

local flowguard = Proto("flowguard", "FlowGuard Lab Protocol")

local HEADER_LEN = 32
local MAGIC = "FGPB"
local TYPE_NAMES = { [1] = "Probe request", [2] = "Probe reply", [3] = "Flood" }
local SHORT_TYPES = { [1] = "probe", [2] = "probe-reply", [3] = "flood" }

local fields = {
    kind = ProtoField.string("flowguard.kind", "Kind"),
    magic = ProtoField.string("flowguard.magic", "Magic"),
    version = ProtoField.uint8("flowguard.version", "Version", base.DEC),
    type = ProtoField.uint8("flowguard.type", "Message type", base.DEC, TYPE_NAMES),
    hdr_len = ProtoField.uint16("flowguard.hdr_len", "Header length", base.DEC),
    session = ProtoField.uint32("flowguard.session", "Session ID", base.HEX),
    seq = ProtoField.uint32("flowguard.seq", "Sequence", base.DEC),
    tx_time = ProtoField.absolute_time("flowguard.tx_time", "Sender time", base.UTC),
    payload_len = ProtoField.uint16("flowguard.payload_len", "Padding length", base.DEC),
    flags = ProtoField.uint16("flowguard.flags", "Flags", base.HEX),
    crc = ProtoField.uint32("flowguard.crc", "CRC32", base.HEX),
    crc_ok = ProtoField.bool("flowguard.crc_ok", "CRC32 valid"),
    source_name = ProtoField.string("flowguard.source_name", "Source name"),
    phase = ProtoField.string("flowguard.phase", "Phase"),
    text_seq = ProtoField.uint32("flowguard.text_seq", "Text sequence", base.DEC),
}
flowguard.fields = {
    fields.kind, fields.magic, fields.version, fields.type, fields.hdr_len, fields.session,
    fields.seq, fields.tx_time, fields.payload_len, fields.flags, fields.crc, fields.crc_ok,
    fields.source_name, fields.phase, fields.text_seq,
}

local ef_crc_bad = ProtoExpert.new("flowguard.crc.bad", "FlowGuard CRC32 mismatch",
                                   expert.group.CHECKSUM, expert.severity.ERROR)
local ef_malformed = ProtoExpert.new("flowguard.malformed", "Inconsistent FGPB header",
                                     expert.group.MALFORMED, expert.severity.WARN)
flowguard.experts = { ef_crc_bad, ef_malformed }

flowguard.prefs.validate_crc = Pref.bool("Validate CRC32", true,
                                         "Recompute the FGPB CRC32 and flag mismatches")

-- Bitwise shim: bit32 on Lua 5.2; native operators on Lua 5.3+ (compiled lazily
-- so Lua 5.2 never parses them).
local band, bxor, rshift
if bit32 then
    band, bxor, rshift = bit32.band, bit32.bxor, bit32.rshift
else
    band = load("return function(a, b) return a & b end")()
    bxor = load("return function(a, b) return a ~ b end")()
    rshift = load("return function(a, n) return (a & 0xFFFFFFFF) >> n end")()
end

local CRC_TABLE = {}
for i = 0, 255 do
    local c = i
    for _ = 1, 8 do
        if band(c, 1) == 1 then
            c = bxor(0xEDB88320, rshift(c, 1))
        else
            c = rshift(c, 1)
        end
    end
    CRC_TABLE[i] = c
end

-- zlib-compatible CRC32 over a sequence of Lua strings.
local function crc32(...)
    local crc = 0xFFFFFFFF
    for _, chunk in ipairs({ ... }) do
        for i = 1, #chunk do
            crc = bxor(CRC_TABLE[band(bxor(crc, chunk:byte(i)), 0xFF)], rshift(crc, 8))
        end
    end
    return bxor(crc, 0xFFFFFFFF)
end

local NS_PER_S = UInt64.new(1000000000)

local function classify(buf)
    local length = buf:len()
    if length == 0 then
        return nil
    end
    if length >= HEADER_LEN and buf:raw(0, 4) == MAGIC then
        return "fgpb"
    end
    local head = buf:raw(0, math.min(length, 32))
    if head:sub(1, 11) == "ddos-probe:" then
        return "legacy_probe"
    elseif head:sub(1, 19) == "FLOWGUARD-LAB-ONLY:" then
        return "flood"
    elseif head:sub(1, 10) == "flowguard:" then
        return "native_flood"
    end
    return nil
end

local function dissect_fgpb(buf, pinfo, subtree)
    local msg_type = buf(5, 1):uint()
    local hdr_len = buf(6, 2):uint()
    local payload_len = buf(24, 2):uint()
    local kind = msg_type == 3 and "flood" or "probe"
    subtree:add(fields.kind, kind):set_generated()
    subtree:add(fields.magic, buf(0, 4))
    subtree:add(fields.version, buf(4, 1))
    subtree:add(fields.type, buf(5, 1))
    local hdr_item = subtree:add(fields.hdr_len, buf(6, 2))
    subtree:add(fields.session, buf(8, 4))
    subtree:add(fields.seq, buf(12, 4))
    local ns = buf(16, 8):uint64()
    local tx = NSTime.new((ns / NS_PER_S):tonumber(), (ns % NS_PER_S):tonumber())
    subtree:add(fields.tx_time, buf(16, 8), tx)
    local len_item = subtree:add(fields.payload_len, buf(24, 2))
    subtree:add(fields.flags, buf(26, 2))
    local crc_item = subtree:add(fields.crc, buf(28, 4))

    if buf(4, 1):uint() ~= 1 or hdr_len ~= HEADER_LEN then
        hdr_item:add_proto_expert_info(ef_malformed, "Unsupported FGPB version or header length")
    end
    if buf:reported_len() ~= HEADER_LEN + payload_len then
        len_item:add_proto_expert_info(ef_malformed, "Datagram length disagrees with payload_len")
    end

    local crc_text = ""
    if flowguard.prefs.validate_crc and buf:len() == buf:reported_len() then
        local padding = buf:len() > HEADER_LEN and buf:raw(HEADER_LEN, buf:len() - HEADER_LEN) or ""
        local computed = crc32(buf:raw(0, 28), padding)
        local ok = computed == buf(28, 4):uint()
        subtree:add(fields.crc_ok, buf(28, 4), ok):set_generated()
        if ok then
            crc_text = " crc=ok"
            crc_item:append_text(" [correct]")
        else
            crc_text = " crc=BAD"
            crc_item:append_text(string.format(" [incorrect, should be 0x%08x]", computed))
            crc_item:add_proto_expert_info(ef_crc_bad)
        end
    end
    pinfo.cols.info:set(string.format("FGPB %s seq=%d session=0x%08x len=%d%s",
        SHORT_TYPES[msg_type] or ("type" .. msg_type), buf(12, 4):uint(), buf(8, 4):uint(),
        buf:reported_len(), crc_text))
end

local function dissect_text(buf, pinfo, subtree, kind)
    local text = buf:raw(0, math.min(buf:len(), 96))
    subtree:add(fields.kind, kind):set_generated()
    if kind == "legacy_probe" then
        local seq = text:match("^ddos%-probe:(%d+):%d+")
        if seq then
            subtree:add(fields.text_seq, buf(11, #seq), tonumber(seq))
            pinfo.cols.info:set("FlowGuard legacy text probe seq=" .. seq)
        else
            pinfo.cols.info:set("FlowGuard legacy text probe")
        end
    elseif kind == "flood" then
        pinfo.cols.info:set(string.format("FlowGuard Mininet lab flood (%d bytes)", buf:reported_len()))
    else
        local source, phase, seq = text:match("^flowguard:([%w_%-]+):([%w_%-]+):(%d+):%d+")
        if source then
            local offset = 10
            subtree:add(fields.source_name, buf(offset, #source))
            offset = offset + #source + 1
            subtree:add(fields.phase, buf(offset, #phase))
            offset = offset + #phase + 1
            subtree:add(fields.text_seq, buf(offset, #seq), tonumber(seq))
            pinfo.cols.info:set(string.format("FlowGuard native lab %s phase=%s seq=%s", source, phase, seq))
        else
            pinfo.cols.info:set("FlowGuard native lab payload")
        end
    end
end

function flowguard.dissector(buf, pinfo, tree)
    local kind = classify(buf)
    if not kind then
        return 0
    end
    pinfo.cols.protocol:set("FlowGuard")
    local subtree = tree:add(flowguard, buf(), "FlowGuard Lab Protocol")
    if kind == "fgpb" then
        dissect_fgpb(buf, pinfo, subtree)
    else
        dissect_text(buf, pinfo, subtree, kind)
    end
    return buf:len()
end

local function heuristic(buf, pinfo, tree)
    if classify(buf) == nil then
        return false
    end
    flowguard.dissector(buf, pinfo, tree)
    return true
end

flowguard:register_heuristic("udp", heuristic)
DissectorTable.get("udp.port"):add_for_decode_as(flowguard)
