import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from traffic.probe_protocol import FLOOD, encode

ROOT = Path(__file__).resolve().parents[1]
DISSECTOR = ROOT / "wireshark/flowguard.lua"
TX_NS = 1_700_000_000_123_456_789
LUAC = next((shutil.which(name) for name in ("luac5.4", "luac5.3", "luac5.2", "luac", "texluac")
             if shutil.which(name)), None)
LUA = next((shutil.which(name) for name in ("lua5.4", "lua5.3", "lua5.2", "lua", "texlua")
            if shutil.which(name)), None)
TSHARK = shutil.which("tshark")


def corrupted(packet):
    data = bytearray(packet)
    data[-1] ^= 0x01
    return bytes(data)


PAYLOADS = [
    encode(7, 0x1234ABCD, TX_NS, total_bytes=64),
    corrupted(encode(8, 0x1234ABCD, TX_NS, total_bytes=64)),
    encode(3, 0x99, TX_NS, FLOOD, 128),
    encode(9, 0x1, TX_NS, total_bytes=32),
    b"ddos-probe:12:1700000000000000000",
    b"FLOWGUARD-LAB-ONLY:".ljust(128, b"X"),
    b"flowguard:a1:attack:5:1700000000000000000".ljust(128, b"."),
    b"hello, not a lab packet",
]


def ipv4_checksum(header):
    total = sum(struct.unpack("!10H", header))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def udp_frame(payload, sport=50000, dport=50001):
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                     bytes([10, 0, 0, 11]), bytes([10, 0, 0, 10]))
    ip = ip[:10] + struct.pack("!H", ipv4_checksum(ip)) + ip[12:]
    return b"\x02\x00\x00\x00\x00\x0a" + b"\x02\x00\x00\x00\x00\x0b" + b"\x08\x00" + ip + udp


def write_pcap(path, payloads):
    with open(path, "wb") as stream:
        stream.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for index, payload in enumerate(payloads):
            frame = udp_frame(payload)
            stream.write(struct.pack("<IIII", 1_700_000_000 + index, 0, len(frame), len(frame)) + frame)


def lua_string(data):
    return '"' + "".join(f"\\{byte:03d}" for byte in data) + '"'


# Minimal stand-ins for the Wireshark Lua API used by flowguard.lua.
HARNESS = r"""
if NO_BIT32 then bit32 = nil end
local records
local function field(kind) return function(abbr) return {abbr = abbr, kind = kind} end end
ProtoField = setmetatable({}, {__index = function(_, kind) return field(kind) end})
base = {NONE = 0, DEC = 1, HEX = 2, UTC = 3}
expert = {group = {CHECKSUM = 1, MALFORMED = 2}, severity = {ERROR = 1, WARN = 2}}
ProtoExpert = {new = function(abbr) return {expert = abbr} end}
Pref = {bool = function(_, default) return default end}
NSTime = {new = function(secs, nsecs) return {secs = secs, nsecs = nsecs} end}
local U = {}
U.__index = U
local function u64(value) return setmetatable({value = value}, U) end
U.__div = function(a, b) return u64(math.floor(a.value / b.value)) end
U.__mod = function(a, b) return u64(a.value % b.value) end
function U:tonumber() return self.value end
UInt64 = {new = u64}
local heuristic
function Proto(name)
    local proto = {name = name, prefs = {}}
    function proto:register_heuristic(list, fn) heuristic = fn end
    return proto
end
DissectorTable = {get = function() return {add_for_decode_as = function() end} end}

local function tvb(data)
    local function range(off, len)
        off = off or 0
        len = len or (#data - off)
        assert(off >= 0 and len >= 0 and off + len <= #data, "range out of bounds")
        local r = {off = off}
        function r:uint() local v = 0 for i = off + 1, off + len do v = v * 256 + data:byte(i) end return v end
        function r:uint64() return u64(r:uint()) end
        function r:string() return data:sub(off + 1, off + len) end
        return r
    end
    local t = {}
    function t:len() return #data end
    function t:reported_len() return #data end
    function t:raw(off, len)
        assert(off >= 0 and len >= 0 and off + len <= #data, "raw out of bounds")
        return data:sub(off + 1, off + len)
    end
    return setmetatable(t, {__call = function(_, off, len) return range(off, len) end})
end

local function item()
    local it = {}
    function it:add(f, a, b)
        if f.abbr then
            local value = a
            if type(a) == "table" and a.off ~= nil then
                if b ~= nil then value = b elseif f.kind == "string" then value = a:string() else value = a:uint() end
            end
            if type(value) == "table" then value = value.secs end
            records[f.abbr] = tostring(value)
        end
        return item()
    end
    function it:set_generated() return self end
    function it:append_text() return self end
    function it:add_proto_expert_info(e) records.expert = e.expert end
    return it
end

local function column() return {set = function(self, text) self.text = text end} end

dofile(DISSECTOR)
for index, data in ipairs(PACKETS) do
    records = {}
    local pinfo = {cols = {protocol = column(), info = column()}}
    local accepted = heuristic(tvb(data), pinfo, item())
    local keys = {"flowguard.kind", "flowguard.seq", "flowguard.crc_ok", "flowguard.text_seq",
                  "flowguard.source_name", "flowguard.phase", "flowguard.tx_time", "expert"}
    local out = {tostring(accepted)}
    for _, key in ipairs(keys) do out[#out + 1] = records[key] or "" end
    out[#out + 1] = pinfo.cols.info.text or ""
    print(table.concat(out, "|"))
end
"""

EXPECTED = [
    ["true", "probe", "7", "true", "", "", "", "1700000000", ""],
    ["true", "probe", "8", "false", "", "", "", "1700000000", "flowguard.crc.bad"],
    ["true", "flood", "3", "true", "", "", "", "1700000000", ""],
    ["true", "probe", "9", "true", "", "", "", "1700000000", ""],
    ["true", "legacy_probe", "", "", "12", "", "", "", ""],
    ["true", "flood", "", "", "", "", "", "", ""],
    ["true", "native_flood", "", "", "5", "a1", "attack", "", ""],
    ["false", "", "", "", "", "", "", "", ""],
]


class DissectorSourceTests(unittest.TestCase):
    @unittest.skipUnless(LUAC, "no luac available")
    def test_lua_syntax(self):
        result = subprocess.run([LUAC, "-p", str(DISSECTOR)], capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(LUA, "no Lua interpreter available")
    def test_dissector_logic_with_mock_wireshark_api(self):
        packets = "PACKETS = {" + ", ".join(lua_string(payload) for payload in PAYLOADS) + "}\n"
        with tempfile.TemporaryDirectory() as directory:
            for no_bit32 in (False, True):
                with self.subTest(no_bit32=no_bit32):
                    harness = Path(directory) / f"harness_{int(no_bit32)}.lua"
                    harness.write_text(f"NO_BIT32 = {str(no_bit32).lower()}\n"
                                       f"DISSECTOR = {lua_string(str(DISSECTOR).encode())}\n"
                                       + packets + HARNESS, encoding="utf-8")
                    result = subprocess.run([LUA, str(harness)], capture_output=True, text=True,
                                            timeout=30, check=False)
                    self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
                    rows = [line.split("|") for line in result.stdout.splitlines()]
                    self.assertEqual([row[:9] for row in rows], EXPECTED)
                    self.assertEqual(rows[0][9], "FGPB probe seq=7 session=0x1234abcd len=64 crc=ok")
                    self.assertEqual(rows[1][9], "FGPB probe seq=8 session=0x1234abcd len=64 crc=BAD")

    def test_profile_files(self):
        profile = ROOT / "wireshark/FlowGuard"
        graphs = (profile / "io_graphs").read_text(encoding="utf-8").splitlines()
        self.assertTrue(any('"Probe requests offered","flowguard.type == 1 && frame.interface_name == '
                            '\\x22client-offered\\x22"' in line for line in graphs))
        buttons = [line for line in (profile / "dfilter_buttons").read_text(encoding="utf-8").splitlines()
                   if line and not line.startswith("#")]
        self.assertEqual(len(buttons), 6)
        for line in buttons:
            self.assertTrue(line.startswith('"TRUE","') and line.endswith('",""'), line)
        self.assertIn('"FlowGuard CRC errors","flowguard.crc_ok == 0"', "\n".join(buttons))


@unittest.skipUnless(TSHARK, "tshark is not installed")
class TsharkDissectorTests(unittest.TestCase):
    def test_tshark_decodes_lab_payloads(self):
        version = subprocess.run([TSHARK, "-v"], capture_output=True, text=True, check=False).stdout
        if "Lua" not in version:
            self.skipTest("tshark built without Lua")
        with tempfile.TemporaryDirectory() as directory:
            pcap = Path(directory) / "flowguard.pcap"
            write_pcap(pcap, PAYLOADS)
            result = subprocess.run(
                [TSHARK, "-X", f"lua_script:{DISSECTOR}", "-r", str(pcap), "-T", "fields",
                 "-e", "flowguard.seq", "-e", "flowguard.crc_ok", "-e", "flowguard.kind", "-e", "flowguard.text_seq"],
                capture_output=True, text=True, timeout=60, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = [line.split("\t") for line in result.stdout.splitlines()]
        self.assertEqual(len(rows), len(PAYLOADS))
        truthy, falsy = {"1", "True", "TRUE", "true"}, {"0", "False", "FALSE", "false"}
        self.assertEqual((rows[0][0], rows[0][2]), ("7", "probe"))
        self.assertIn(rows[0][1], truthy)
        self.assertEqual((rows[1][0], rows[1][2]), ("8", "probe"))
        self.assertIn(rows[1][1], falsy)
        self.assertEqual(rows[2][2], "flood")
        self.assertEqual((rows[4][2], rows[4][3]), ("legacy_probe", "12"))
        self.assertEqual(rows[5][2], "flood")
        self.assertEqual((rows[6][2], rows[6][3]), ("native_flood", "5"))
        self.assertEqual("".join(rows[7]).strip(), "")


if __name__ == "__main__":
    unittest.main()
