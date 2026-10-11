#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 lahiru
# Requires: pip install reedsolo cryptography   |   Run: python3 tools/vectors.py (expects ALL OK)
# Outputs (after ALL OK): --emit-c PATH (vectors_generated.h), --emit-md PATH (PROTOCOL.md Appendix A body A.1..A.15),
#   --emit-kmesh-hash8 PATH (rewrites the s_test_kmesh_hash8 table in place in br_crypto.c)
"""Braid v0.9 test vectors. Needs reedsolo (RS cross-check) and cryptography (AES-CCM)."""
import struct, hmac, hashlib, sys
import reedsolo
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

def crc16(data, init=0xFFFF):
    crc = init
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc
assert crc16(b"123456789") == 0x29B1
EXP = [0]*512; LOG = [0]*256; x = 1
for i in range(255):
    EXP[i] = x; LOG[x] = i; x <<= 1
    if x & 0x100: x ^= 0x11D
for i in range(255, 512): EXP[i] = EXP[i-255]
def gmul(a, b): return 0 if a == 0 or b == 0 else EXP[LOG[a] + LOG[b]]
def gen_poly(nsym):
    g = [1]
    for i in range(nsym):
        ng = [0]*(len(g)+1)
        for j, c in enumerate(g):
            ng[j] ^= c; ng[j+1] ^= gmul(c, EXP[i])
        g = ng
    return g
def rs_encode(msg, nsym):
    g = gen_poly(nsym); buf = list(msg) + [0]*nsym
    for i in range(len(msg)):
        c = buf[i]
        if c:
            for j in range(1, len(g)): buf[i+j] ^= gmul(g[j], c)
    return bytes(buf[len(msg):])
def cobs_encode(data):
    out = bytearray(); code = 1; block = bytearray()
    for b in data:
        if b == 0:
            out.append(code); out += block; block = bytearray(); code = 1
        else:
            block.append(b); code += 1
            if code == 0xFF:
                out.append(code); out += block; block = bytearray(); code = 1
    out.append(code); out += block
    return bytes(out)
def hkdf_extract(salt, ikm): return hmac.new(salt, ikm, hashlib.sha256).digest()
def hkdf_expand(prk, info, L):
    out = b""; t = b""; i = 1
    while len(out) < L:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest(); out += t; i += 1
    return out[:L]
def hkdf(ikm, salt, info, L): return hkdf_expand(hkdf_extract(salt, ikm), info, L)

# ---- v0.6 header: 19 bytes (hop_seq u32), SEEK 22 ----
def hdr(vf, t, src, dst, prev, nxt, ttl, hops, hop_seq, sess, seq, plen, path_mtu=None, path_cost=None):
    h = struct.pack("<BBHHHHBI", vf, t, src, dst, prev, nxt, (ttl << 4) | hops, hop_seq)
    if t == 0x01: h += struct.pack("<HB", path_mtu, path_cost)
    return h + struct.pack("<BHB", sess, seq, plen)
def e2e(h): return h[:6] + h[-4:]
def nonce(direction, src, dst, sess, ctr_hi, seq): return struct.pack("<BHHBIHB", direction, src, dst, sess, ctr_hi, seq, 0)
def ccm(key, h, direction, ctr_hi, clear, secret):
    """clear = plaintext prefix (in AAD), secret = encrypted part. Returns (payload bytes, tag, nonce, aad)."""
    src, dst = struct.unpack("<HH", h[2:6]); sess = h[-4]; seq = struct.unpack("<H", h[-3:-1])[0]
    n = nonce(direction, src, dst, sess, ctr_hi, seq)
    a = e2e(h) + struct.pack("<I", ctr_hi) + clear
    ct = AESCCM(key, tag_length=8).encrypt(n, secret, a)
    return clear + ct[:-8], ct[-8:], n, a
def hoptag(khop, upto): return hmac.new(khop, upto, hashlib.sha256).digest()[:4]
def frame(h, body, tag=b"", khop=None):
    f = h + body + tag
    if tag: f += hoptag(khop, f)
    return f + struct.pack("<H", crc16(f))

# ---- C header emitter: vectors are recorded as the script computes them; written only with --emit-c PATH ----
EMIT = []; EMIT_NAMES = set()
def _rec(kind, name, comment, val):
    assert name not in EMIT_NAMES, name
    EMIT_NAMES.add(name); EMIT.append((kind, name, comment, val))
def eb(name, comment, data):
    """record a byte-array vector (empty data is skipped: C has no zero-length arrays)"""
    data = bytes(data)
    if data: _rec("b", name, comment, data)
def ei(name, comment, val, signed=False):
    """record a scalar (macro)"""
    _rec("i", name, comment, (int(val), signed))
def ef(name, comment, frm):
    """record a full frame plus its CRC-16 scalar"""
    eb(name + "_FRAME", comment, frm); ei(name + "_CRC", comment + " - CRC-16 (little-endian trailer)", crc16(frm[:-2]))
def write_c_header(path):
    L = ["// SPDX-License-Identifier: AGPL-3.0-or-later",
         "// SPDX-FileCopyrightText: 2026 lahiru",
         "/* Braid Appendix A test vectors.",
         " * GENERATED FILE - DO NOT EDIT.",
         " * Regenerate with: python3 tools/vectors.py --emit-c firmware/test/host/vectors_generated.h",
         " * Every value below is computed by tools/vectors.py (the oracle the spec was built from). TEST ONLY keys.",
         " */",
         "#ifndef BRAID_VECTORS_GENERATED_H", "#define BRAID_VECTORS_GENERATED_H", "",
         "#include <stddef.h>", "#include <stdint.h>", ""]
    for kind, name, comment, val in EMIT:
        if kind == "b":
            L.append("/* %s */" % comment)
            L.append("#define %s_LEN %du" % (name, len(val)))
            body = ",\n    ".join(", ".join("0x%02x" % b for b in val[i:i+12]) for i in range(0, len(val), 12))
            L.append("static const uint8_t %s[%s_LEN] = {\n    %s\n};" % (name, name, body))
        elif kind == "i":
            v, sg = val
            L.append("/* %s */" % comment)
            if sg: L.append("#define %s (%d)" % (name, v))
            else: L.append("#define %s 0x%04Xu" % (name, v) if v < 0x10000 else "#define %s 0x%08Xu" % (name, v))
        elif kind == "t":
            L.append("/* %s */" % comment); L.append(val)
        L.append("")
    L.append("#endif /* BRAID_VECTORS_GENERATED_H */")
    out = "\n".join(L) + "\n"
    assert all(ord(c) < 128 for c in out)
    with open(path, "w") as fh: fh.write(out)

LAST = [b""]
def show(name, f):
    LAST[0] = f; print("%s (%d): %s  crc=0x%04X" % (name, len(f), f.hex(), crc16(f[:-2])))

print("==== Braid v0.9 vectors ====")
print("A.1 CRC('123456789') = 0x%04X" % crc16(b"123456789"))
eb("BRV_A1_CRC_INPUT", "A.1 CRC-16/CCITT-FALSE input: ASCII '123456789'", b"123456789")
ei("BRV_A1_CRC_EXPECTED", "A.1 expected CRC-16 of BRV_A1_CRC_INPUT", crc16(b"123456789"))
# A.2/A.3 bench SEEK: pre_ctr 1, nonce_s, caps 0x0033, max_frame 250, epoch 0, minor 0, fw 1
seek_pay = struct.pack("<IIHHBBI", 1, 0xA1B2C3D4, 0x0033, 250, 0, 0, 1)
h2 = hdr(0x10, 0x01, 0x1234, 0xFF01, 0x1234, 0xFFFF, 4, 0, 1, 0, 1, len(seek_pay), 250, 0)
show("A.2 SEEK espnow", frame(h2, seek_pay))
eb("BRV_A2_HEADER", "A.2 SEEK on ESP-NOW (bench, no tags): 22-byte header", h2)
eb("BRV_A2_PAYLOAD", "A.2 SEEK payload: pre_ctr 1, nonce_s 0xA1B2C3D4, caps 0x0033, max_frame 250, epoch 0, minor 0, fw 1", seek_pay)
ef("BRV_A2", "A.2 SEEK on ESP-NOW full frame (header || payload || crc)", LAST[0])
h3 = hdr(0x10, 0x01, 0x1234, 0xFF01, 0x1234, 0xFFFF, 4, 0, 1, 0, 1, len(seek_pay), 242, 0)
f3 = frame(h3, seek_pay); show("A.3 SEEK uart", f3)
eb("BRV_A3_HEADER", "A.3 SEEK on UART (path_mtu 242): 22-byte header", h3)
ef("BRV_A3", "A.3 SEEK on UART full frame (header || payload || crc)", f3)
par = rs_encode(f3, 8); assert par == bytes(reedsolo.RSCodec(8, fcr=0, prim=0x11D, generator=2).encode(f3))[-8:]
print("A.3 RS parity: %s" % par.hex()); wire = cobs_encode(f3 + par) + b"\x00"; print("A.3 COBS wire (%d): %s" % (len(wire), wire.hex()))
ei("BRV_A3_RS_NSYM", "A.3 RS parity symbols for the UART frame", 8)
eb("BRV_A3_RS_PARITY", "A.3 RS(8) parity over BRV_A3_FRAME", par)
eb("BRV_A3_COBS_INPUT", "A.3 bytes fed to COBS: frame || RS parity", f3 + par)
eb("BRV_A3_COBS_WIRE", "A.3 COBS-encoded wire bytes including trailing 0x00 delimiter", wire)
assert rs_encode(b"ProbeLink", 6).hex() == "2876025691f1"
rs4a = b"ProbeLink"; rs4b = bytes.fromhex("123456789a")
assert rs_encode(rs4b, 1) == bytes([0x92]) and rs_encode(rs4b, 1)[0] == (0x12 ^ 0x34 ^ 0x56 ^ 0x78 ^ 0x9A)
eb("BRV_A4_RS6_MESSAGE", "A.4 RS(6) standalone message: ASCII 'ProbeLink'", rs4a)
ei("BRV_A4_RS6_NSYM", "A.4 RS(6) nsym", 6)
eb("BRV_A4_RS6_PARITY", "A.4 RS(6) parity of BRV_A4_RS6_MESSAGE", rs_encode(rs4a, 6))
eb("BRV_A4_RS1_MESSAGE", "A.4 RS(1) standalone message: 12 34 56 78 9a", rs4b)
ei("BRV_A4_RS1_NSYM", "A.4 RS(1) nsym", 1)
eb("BRV_A4_RS1_PARITY", "A.4 RS(1) parity of BRV_A4_RS1_MESSAGE (equals XOR of the message)", rs_encode(rs4b, 1))

# ---- A.5 cross-frame FEC: parity block i = RS(m) parity of the column of block bytes, per byte position ----
def fec_parity(blocks, m):
    par = [bytearray() for _ in range(m)]
    for c in range(len(blocks[0])):
        p = rs_encode(bytes(b[c] for b in blocks), m)
        for i in range(m): par[i].append(p[i])
    return [bytes(x) for x in par]
def fec_erasure_decode(blocks, parity, erased):
    codec = reedsolo.RSCodec(len(parity), fcr=0, prim=0x11D, generator=2); out = [bytearray() for b in blocks]
    for c in range(len(blocks[0])):
        cw = bytearray([b[c] for b in blocks] + [p[c] for p in parity])
        for e in erased: cw[e] = 0
        dec = bytes(codec.decode(bytes(cw), erase_pos=list(erased))[0])
        for i in range(len(blocks)): out[i].append(dec[i])
    return [bytes(x) for x in out]
fa_blocks = [bytes.fromhex("0301020300"), bytes.fromhex("0410203040")]
fa_par = fec_parity(fa_blocks, 1); assert [x.hex() for x in fa_par] == ["0711223340"]
fb_blocks = [bytes.fromhex(x) for x in ("02aabb00", "03112233", "01ff0000", "03010203")]
fb_par = fec_parity(fb_blocks, 2); assert [x.hex() for x in fb_par] == ["2d012d19", "2e44b629"]
fb_dec = fec_erasure_decode(fb_blocks, fb_par, (1, 3)); assert fb_dec == fb_blocks
ei("BRV_A5_K2M1_K", "A.5 FEC k2/m1: data block count k", 2); ei("BRV_A5_K2M1_M", "A.5 FEC k2/m1: parity block count m", 1)
for i, b in enumerate(fa_blocks): eb("BRV_A5_K2M1_BLOCK%d" % i, "A.5 FEC k2/m1 data block %d" % i, b)
eb("BRV_A5_K2M1_PARITY0", "A.5 FEC k2/m1 expected parity block 0", fa_par[0])
ei("BRV_A5_K4M2_K", "A.5 FEC k4/m2: data block count k", 4); ei("BRV_A5_K4M2_M", "A.5 FEC k4/m2: parity block count m", 2)
for i, b in enumerate(fb_blocks): eb("BRV_A5_K4M2_BLOCK%d" % i, "A.5 FEC k4/m2 data block %d" % i, b)
for i, b in enumerate(fb_par): eb("BRV_A5_K4M2_PARITY%d" % i, "A.5 FEC k4/m2 expected parity block %d" % i, b)
eb("BRV_A5_K4M2_ERASED", "A.5 FEC k4/m2 erasure positions (block indices) to reconstruct", bytes([1, 3]))

# ---- keys ----
K_site = bytes(range(32)); S, P, R, M = 0x1234, 0x0042, 0x0099, 0x0001
# KDF domain-separation labels (spec 8.2): the only place the script names them.
LBL_V1 = b"Braid-v1"; LBL_MESH = b"Braid-mesh"; LBL_PAIR = b"Braid-pair"; LBL_NODE = b"Braid-node"
def K_mesh(E): return hkdf(K_site, LBL_MESH, bytes([E]), 32)
def K_hop(E): return hkdf_expand(hkdf_extract(LBL_V1, K_mesh(E)), b"hop", 32)
def Ke_mesh(E): return hkdf_expand(hkdf_extract(LBL_V1, K_mesh(E)), b"mesh-enc", 16)
def K_pair(A, B, E): return hkdf(K_site, LBL_PAIR, struct.pack("<HHB", min(A,B), max(A,B), E), 32)
def K_node(N): return hkdf(K_site, LBL_NODE, struct.pack("<H", N), 32)
print("A.6 K_mesh(1) = %s" % K_mesh(1).hex()); print("A.6 K_hop(1) = %s" % K_hop(1).hex()); print("A.6 K_hop(0) = %s" % K_hop(0).hex())
print("A.6 Ke_mesh(1) = %s" % Ke_mesh(1).hex()); print("A.6 K_pair(0042,1234,1) = %s" % K_pair(S, P, 1).hex())
PRK = hkdf_extract(LBL_V1, K_pair(S, P, 1)); print("A.6 PRK = %s" % PRK.hex())
eb("BRV_A6_K_SITE", "A.6 K_site (TEST ONLY) = bytes 0x00..0x1F", K_site)
eb("BRV_A6_K_MESH_1", "A.6 K_mesh(1) = HKDF(K_site, '%s', 01, 32)" % LBL_MESH.decode(), K_mesh(1))
eb("BRV_A6_K_HOP_1", "A.6 K_hop(1)", K_hop(1))
eb("BRV_A6_K_HOP_0", "A.6 K_hop(0)", K_hop(0))
eb("BRV_A6_KE_MESH_1", "A.6 Ke_mesh(1) (16 bytes)", Ke_mesh(1))
eb("BRV_A6_K_PAIR_0042_1234_1", "A.6 K_pair(0042, 1234, 1)", K_pair(S, P, 1))
eb("BRV_A6_PRK", "A.6 PRK = Extract('%s', K_pair(0042, 1234, 1))" % LBL_V1.decode(), PRK)

# ---- A.8 keyed SEEK, 2 hops ----
pre_s = 0x00010001
spay = struct.pack("<IIHHBBI", pre_s, 0xA1B2C3D4, 0x003B, 250, 1, 0, 1)
hs1 = hdr(0x12, 0x01, S, 0xFF01, S, 0xFFFF, 4, 0, 7, 0, pre_s & 0xFFFF, len(spay), 250, 0)
body, stag, sn, sa = ccm(Ke_mesh(1), hs1, 0, pre_s >> 16, spay, b"")
hs2 = hdr(0x12, 0x01, S, 0xFF01, R, 0xFFFF, 3, 1, 0x00010130, 0, pre_s & 0xFFFF, len(spay), 250, 1)
_, stag2, _, _ = ccm(Ke_mesh(1), hs2, 0, pre_s >> 16, spay, b""); assert stag == stag2
print("A.8 SEEK nonce = %s ; AAD = %s ; ccm_tag = %s" % (sn.hex(), sa.hex(), stag.hex()))
show("A.8 SEEK hop1", frame(hs1, spay, stag, K_hop(1))); show("A.8 SEEK hop2", frame(hs2, spay, stag, K_hop(1)))
eb("BRV_A8_SEEK_HDR_HOP1", "A.8 keyed SEEK hop 1 (S, hop_seq 7) header, 22 bytes", hs1)
eb("BRV_A8_SEEK_HDR_HOP2", "A.8 keyed SEEK hop 2 (R, hop_seq 0x00010130, hops 1) header, 22 bytes", hs2)
eb("BRV_A8_SEEK_PAYLOAD", "A.8 keyed SEEK clear payload (pre_ctr 0x00010001, caps 0x003B, key_epoch 1)", spay)
eb("BRV_A8_SEEK_KEY", "A.8 keyed SEEK CCM key: Ke_mesh(1)", Ke_mesh(1))
eb("BRV_A8_SEEK_NONCE", "A.8 keyed SEEK CCM nonce (13 bytes)", sn)
eb("BRV_A8_SEEK_AAD", "A.8 keyed SEEK CCM AAD = e2e header || ctr_hi || payload", sa)
eb("BRV_A8_SEEK_CCM_TAG", "A.8 keyed SEEK ccm_tag (empty plaintext, 8 bytes)", stag)
eb("BRV_A8_SEEK_HOP_KEY", "A.8 keyed SEEK hop_tag key: K_hop(1)", K_hop(1))
ef("BRV_A8_SEEK_HOP1", "A.8 keyed SEEK hop 1 full frame (54 bytes)", frame(hs1, spay, stag, K_hop(1)))
ef("BRV_A8_SEEK_HOP2", "A.8 keyed SEEK hop 2 full frame (54 bytes)", frame(hs2, spay, stag, K_hop(1)))

# ---- A.9 HELLO (pre_ctr 0x00010007, ctr_hi 1), BIND ----
T0 = hashlib.sha256(e2e(hs1) + spay).digest()
Ke_hello = hkdf_expand(PRK, b"hello" + struct.pack("<HH", S, P) + T0, 16)
pre_p = 0x00010007
h_clear = struct.pack("<I", pre_p)
h_secret = struct.pack("<IIIHHbBBBI", pre_s, 0xA1B2C3D4, 0x0BADF00D, 0x003B, 250, -61, 0, 1, 0, 2)  # seek_ctr echo, nonce_s, nonce_p, caps, max_frame, rssi, status, path_cost, minor, fw
hh = hdr(0x12, 0x02, P, S, P, R, 4, 0, 3, 0, pre_p & 0xFFFF, 4 + len(h_secret))
hbody, htag, hn, ha = ccm(Ke_hello, hh, 1, pre_p >> 16, h_clear, h_secret)
# sender side: decrypt with Ke_hello using ctr_hi from the clear pre_ctr
rx_ctr = struct.unpack("<I", hbody[:4])[0]
dec = AESCCM(Ke_hello, tag_length=8).decrypt(nonce(1, P, S, 0, rx_ctr >> 16, pre_p & 0xFFFF), hbody[4:] + htag, e2e(hh) + struct.pack("<I", rx_ctr >> 16) + hbody[:4])
assert dec == h_secret
T = hashlib.sha256(e2e(hs1) + spay + e2e(hh) + h_clear + h_secret).digest()
Ke_hs = hkdf_expand(PRK, b"hs" + struct.pack("<HH", S, P) + T, 16)
sess = 7
Ke_s2p = hkdf_expand(PRK, b"s2p" + struct.pack("<HHB", S, P, sess) + T, 16)
Ke_p2s = hkdf_expand(PRK, b"p2s" + struct.pack("<HHB", S, P, sess) + T, 16)
print("A.9 T0 = %s" % T0.hex()); print("A.9 Ke_hello = %s" % Ke_hello.hex())
print("A.9 HELLO secret plaintext = %s" % h_secret.hex())
print("A.9 HELLO nonce = %s ; AAD = %s" % (hn.hex(), ha.hex()))
print("A.9 HELLO payload (clear pre_ctr || ciphertext) = %s ; tag = %s" % (hbody.hex(), htag.hex()))
show("A.9 HELLO hop1", frame(hh, hbody, htag, K_hop(1)))
eb("BRV_A9_T0", "A.9 T0 = SHA-256(SEEK e2e header || SEEK payload)", T0)
eb("BRV_A9_KE_HELLO", "A.9 Ke_hello = Expand(PRK, 'hello' || S || P || T0, 16)", Ke_hello)
eb("BRV_A9_HELLO_HEADER", "A.9 HELLO header (19 bytes)", hh)
eb("BRV_A9_HELLO_CLEAR", "A.9 HELLO clear pre_ctr 0x00010007", h_clear)
eb("BRV_A9_HELLO_SECRET", "A.9 HELLO secret plaintext (24 bytes)", h_secret)
eb("BRV_A9_HELLO_NONCE", "A.9 HELLO CCM nonce (13 bytes)", hn)
eb("BRV_A9_HELLO_AAD", "A.9 HELLO CCM AAD", ha)
eb("BRV_A9_HELLO_PAYLOAD", "A.9 HELLO payload = clear pre_ctr || ciphertext", hbody)
eb("BRV_A9_HELLO_TAG", "A.9 HELLO CCM tag (8 bytes)", htag)
ei("BRV_A9_HELLO_CTR_HI", "A.9 HELLO ctr_hi (high half of pre_ctr, used in nonce/AAD)", pre_p >> 16)
eb("BRV_A9_HELLO_HOP_TAG", "A.9 HELLO hop_tag (4 bytes, K_hop(1))", LAST[0][-6:-2])
ef("BRV_A9_HELLO", "A.9 HELLO hop 1 full frame (61 bytes)", LAST[0])
print("A.9 T = %s" % T.hex()); print("A.9 Ke_hs = %s ; Ke_s2p = %s ; Ke_p2s = %s" % (Ke_hs.hex(), Ke_s2p.hex(), Ke_p2s.hex()))
eb("BRV_A9_T", "A.9 T = SHA-256(SEEK e2e || SEEK payload || HELLO e2e || HELLO plaintext payload)", T)
eb("BRV_A9_KE_HS", "A.9 Ke_hs (16 bytes)", Ke_hs)
eb("BRV_A9_KE_S2P", "A.9 Ke_s2p (16 bytes), session 7", Ke_s2p)
eb("BRV_A9_KE_P2S", "A.9 Ke_p2s (16 bytes), session 7", Ke_p2s)
ei("BRV_A9_SESSION_ID", "A.9 session id assigned in BIND", sess)
pre_b = 0x00010002
b_clear = struct.pack("<I", pre_b); b_secret = struct.pack("<IIIB", pre_p, 0xA1B2C3D4, 0x0BADF00D, sess)   # hello_ctr echo, nonces, session_id
hb = hdr(0x12, 0x03, S, P, S, R, 4, 0, 8, 0, pre_b & 0xFFFF, 4 + len(b_secret))
bbody, btag, bn, _ = ccm(Ke_hs, hb, 0, pre_b >> 16, b_clear, b_secret)
print("A.9 BIND secret plaintext = %s ; nonce = %s ; payload = %s ; tag = %s" % (b_secret.hex(), bn.hex(), bbody.hex(), btag.hex()))
show("A.9 BIND hop1", frame(hb, bbody, btag, K_hop(1)))
eb("BRV_A9_BIND_HEADER", "A.9 BIND header (19 bytes)", hb)
eb("BRV_A9_BIND_CLEAR", "A.9 BIND clear pre_ctr 0x00010002", b_clear)
eb("BRV_A9_BIND_SECRET", "A.9 BIND secret plaintext (hello_ctr, nonces, session 7; 13 bytes)", b_secret)
eb("BRV_A9_BIND_NONCE", "A.9 BIND CCM nonce (13 bytes), key Ke_hs", bn)
eb("BRV_A9_BIND_PAYLOAD", "A.9 BIND payload = clear pre_ctr || ciphertext", bbody)
eb("BRV_A9_BIND_TAG", "A.9 BIND CCM tag (8 bytes)", btag)
eb("BRV_A9_BIND_HOP_TAG", "A.9 BIND hop_tag (4 bytes, K_hop(1))", LAST[0][-6:-2])
ef("BRV_A9_BIND", "A.9 BIND hop 1 full frame (50 bytes)", LAST[0])

# ---- A.7 DATA direct, A.8 two hops, E-1 hop_tag, A.10 ROC 1 ----
dpay = struct.pack("<BBIB", 1, 0, 1000, 1) + struct.pack("<f", 1.5)
hd = hdr(0x12, 0x10, S, P, S, P, 3, 0, 9, sess, 5, len(dpay))
dbody, dtag, dn, da = ccm(Ke_s2p, hd, 0, 0, b"", dpay)
print("A.7 DATA plaintext = %s ; nonce = %s ; AAD = %s" % (dpay.hex(), dn.hex(), da.hex()))
print("A.7 DATA ciphertext = %s ; tag = %s" % (dbody.hex(), dtag.hex()))
fd = frame(hd, dbody, dtag, K_hop(1)); show("A.7 DATA direct", fd); print("A.7 hop_tag = %s" % fd[-6:-2].hex())
eb("BRV_A7_HEADER", "A.7 DATA direct header (19 bytes): session 7, seq 5, hop_seq 9", hd)
eb("BRV_A7_KEY", "A.7 DATA CCM key: Ke_s2p (A.9)", Ke_s2p)
eb("BRV_A7_PLAINTEXT", "A.7 DATA plaintext: one float32 1.5 at t = 1000 us (11 bytes)", dpay)
eb("BRV_A7_NONCE", "A.7 DATA CCM nonce (13 bytes), ROC 0", dn)
eb("BRV_A7_AAD", "A.7 DATA CCM AAD (14 bytes)", da)
eb("BRV_A7_CIPHERTEXT", "A.7 DATA expected ciphertext (11 bytes)", dbody)
eb("BRV_A7_CCM_TAG", "A.7 DATA expected ccm_tag (8 bytes)", dtag)
eb("BRV_A7_HOP_KEY", "A.7 hop_tag key: K_hop(1)", K_hop(1))
eb("BRV_A7_HOP_TAG", "A.7 hop_tag = HMAC(K_hop(1), frame[0..37])[0..3]", fd[-6:-2])
ef("BRV_A7", "A.7 DATA direct full frame (44 bytes)", fd)
hd1 = hdr(0x12, 0x10, S, P, S, R, 4, 0, 9, sess, 5, len(dpay)); hd2 = hdr(0x12, 0x10, S, P, R, P, 3, 1, 0x00010131, sess, 5, len(dpay))
show("A.8 DATA hop1", frame(hd1, dbody, dtag, K_hop(1))); show("A.8 DATA hop2", frame(hd2, dbody, dtag, K_hop(1)))
show("A.8 DATA hop2 under K_hop(0)", frame(hd2, dbody, dtag, K_hop(0)))
eb("BRV_A8_DATA_HDR_HOP1", "A.8 DATA hop 1 (S -> R) header (19 bytes)", hd1)
eb("BRV_A8_DATA_HDR_HOP2", "A.8 DATA hop 2 (R -> P) header (19 bytes), hop_seq 0x00010131", hd2)
ef("BRV_A8_DATA_HOP1", "A.8 DATA hop 1 (S -> R) full frame (44 bytes)", frame(hd1, dbody, dtag, K_hop(1)))
ef("BRV_A8_DATA_HOP2", "A.8 DATA hop 2 (R -> P) full frame under K_hop(1) (44 bytes)", frame(hd2, dbody, dtag, K_hop(1)))
eb("BRV_A8_DATA_HOP2_K0_KEY", "A.8 hop 2 re-tag key: K_hop(0)", K_hop(0))
eb("BRV_A8_DATA_HOP2_K0_HOP_TAG", "A.8 hop 2 hop_tag under K_hop(0)", LAST[0][-6:-2])
ef("BRV_A8_DATA_HOP2_K0", "A.8 DATA hop 2 re-tagged under K_hop(0) full frame (44 bytes)", LAST[0])
hd_r = hdr(0x12, 0x10, S, P, S, P, 3, 0, 0x2345, sess, 5, len(dpay))
rbody, rtag, rn, _ = ccm(Ke_s2p, hd_r, 0, 1, b"", dpay)
print("A.10 ROC=1 nonce = %s ; ciphertext = %s ; tag = %s" % (rn.hex(), rbody.hex(), rtag.hex()))
show("A.10 DATA ROC=1", frame(hd_r, rbody, rtag, K_hop(1)))
eb("BRV_A10_HEADER", "A.10 DATA at ROC 1 header (19 bytes), hop_seq 0x2345", hd_r)
ei("BRV_A10_ROC", "A.10 ROC used for the second-cycle frame", 1)
eb("BRV_A10_NONCE", "A.10 DATA ROC=1 CCM nonce (13 bytes), key Ke_s2p, plaintext BRV_A7_PLAINTEXT", rn)
eb("BRV_A10_CIPHERTEXT", "A.10 DATA ROC=1 expected ciphertext (11 bytes)", rbody)
eb("BRV_A10_CCM_TAG", "A.10 DATA ROC=1 expected ccm_tag (8 bytes)", rtag)
ef("BRV_A10_DATA_ROC1", "A.10 DATA ROC=1 full frame (44 bytes)", LAST[0])
# ---- A.11 RESUME ----
pre_r = 0x00010003; rpay = struct.pack("<IB", pre_r, 1)
hr = hdr(0x12, 0x31, S, P, S, 0xFFFF, 3, 0, 0x4000, sess, 0x0042, len(rpay))
_, rtg, rnn, _ = ccm(Ke_s2p, hr, 0, 0, rpay, b"")
print("A.11 RESUME nonce = %s ; tag = %s" % (rnn.hex(), rtg.hex())); show("A.11 RESUME hop1", frame(hr, rpay, rtg, K_hop(1)))
eb("BRV_A11_HEADER", "A.11 RESUME flood header (19 bytes): session 7, seq 0x0042, ttl 3, hop_seq 0x4000", hr)
eb("BRV_A11_KEY", "A.11 RESUME CCM key: Ke_s2p (tag over empty plaintext)", Ke_s2p)
eb("BRV_A11_PAYLOAD", "A.11 RESUME clear payload: pre_ctr 0x00010003, flags 01 (5 bytes)", rpay)
eb("BRV_A11_NONCE", "A.11 RESUME CCM nonce (13 bytes), ROC 0", rnn)
eb("BRV_A11_CCM_TAG", "A.11 RESUME expected ccm_tag (8 bytes)", rtg)
eb("BRV_A11_HOP_TAG", "A.11 RESUME hop_tag (4 bytes, K_hop(1))", LAST[0][-6:-2])
ef("BRV_A11_RESUME", "A.11 RESUME hop 1 full frame (38 bytes)", LAST[0])

# ---- A.12 MGMT_REQ (flooded, no route) and MGMT_RESP ----
K_mgmt = hkdf_expand(hkdf_extract(LBL_V1, K_pair(P, M, 1)), b"mgmt" + struct.pack("<HH", P, M), 16)
print("A.12 K_pair(0001,0042,1) = %s ; K_mgmt(0042->0001) = %s" % (K_pair(P, M, 1).hex(), K_mgmt.hex()))
eb("BRV_A12_K_PAIR_0001_0042_1", "A.12 K_pair(0001, 0042, 1)", K_pair(P, M, 1))
eb("BRV_A12_K_MGMT_0042_0001", "A.12 K_mgmt(0042 -> 0001) (16 bytes)", K_mgmt)
pre_m = 0x00010008
m_clear = struct.pack("<I", pre_m)
m_secret = struct.pack("<QBBBBBBI", 123456789, 1, 1, 0x00, 0, 0, 0, 3) + bytes([0x11]*8)   # t1, e_new 1, e_old 1, flags 0, section 0, page 0, chunk 0, bundle_no 3, then 8 report bytes (illustrative)
hm = hdr(0x12, 0x40, P, M, P, 0xFFFF, 4, 0, 4, 0, pre_m & 0xFFFF, 4 + len(m_secret))
mbody, mtag, mn, ma = ccm(K_mgmt, hm, 0, pre_m >> 16, m_clear, m_secret)
print("A.12 MGMT_REQ secret plaintext = %s ; nonce = %s ; AAD = %s" % (m_secret.hex(), mn.hex(), ma.hex()))
print("A.12 MGMT_REQ payload = %s ; tag = %s" % (mbody.hex(), mtag.hex()))
show("A.12 MGMT_REQ flood hop1", frame(hm, mbody, mtag, K_hop(1)))
eb("BRV_A12_REQ_HEADER", "A.12 MGMT_REQ header (19 bytes), flooded, no route", hm)
eb("BRV_A12_REQ_CLEAR", "A.12 MGMT_REQ clear pre_ctr 0x00010008", m_clear)
eb("BRV_A12_REQ_SECRET", "A.12 MGMT_REQ secret plaintext (22 bytes, 8 illustrative report bytes)", m_secret)
eb("BRV_A12_REQ_NONCE", "A.12 MGMT_REQ CCM nonce (13 bytes), key K_mgmt", mn)
eb("BRV_A12_REQ_AAD", "A.12 MGMT_REQ CCM AAD", ma)
eb("BRV_A12_REQ_PAYLOAD", "A.12 MGMT_REQ payload = clear pre_ctr || ciphertext", mbody)
eb("BRV_A12_REQ_TAG", "A.12 MGMT_REQ CCM tag (8 bytes)", mtag)
eb("BRV_A12_REQ_HOP_TAG", "A.12 MGMT_REQ hop_tag (4 bytes, K_hop(1))", LAST[0][-6:-2])
ef("BRV_A12_REQ", "A.12 MGMT_REQ full frame (63 bytes)", LAST[0])
pre_g = 0x00020005
g_clear = struct.pack("<I", pre_g)
g_secret = struct.pack("<IQQQB", pre_m, 123456789, 1700000000000000, 1700000000000500, 0)   # req_ctr echo, t1 echo, t2, t3, flags 0
hg = hdr(0x12, 0x41, M, P, M, R, 4, 0, 0x0005, 0, pre_g & 0xFFFF, 4 + len(g_secret))
gbody, gtag, gn, ga = ccm(K_mgmt, hg, 1, pre_g >> 16, g_clear, g_secret)
print("A.12 MGMT_RESP secret plaintext = %s ; nonce = %s ; AAD = %s" % (g_secret.hex(), gn.hex(), ga.hex()))
print("A.12 MGMT_RESP payload = %s ; tag = %s" % (gbody.hex(), gtag.hex()))
show("A.12 MGMT_RESP hop1", frame(hg, gbody, gtag, K_hop(1)))
eb("BRV_A12_RESP_HEADER", "A.12 MGMT_RESP header (19 bytes)", hg)
eb("BRV_A12_RESP_CLEAR", "A.12 MGMT_RESP clear pre_ctr 0x00020005", g_clear)
eb("BRV_A12_RESP_SECRET", "A.12 MGMT_RESP secret plaintext (req_ctr, t1 echo, t2, t3, flags; 29 bytes)", g_secret)
eb("BRV_A12_RESP_NONCE", "A.12 MGMT_RESP CCM nonce (13 bytes), key K_mgmt", gn)
eb("BRV_A12_RESP_AAD", "A.12 MGMT_RESP CCM AAD", ga)
eb("BRV_A12_RESP_PAYLOAD", "A.12 MGMT_RESP payload = clear pre_ctr || ciphertext", gbody)
eb("BRV_A12_RESP_TAG", "A.12 MGMT_RESP CCM tag (8 bytes)", gtag)
eb("BRV_A12_RESP_HOP_TAG", "A.12 MGMT_RESP hop_tag (4 bytes, K_hop(1))", LAST[0][-6:-2])
ef("BRV_A12_RESP", "A.12 MGMT_RESP full frame (66 bytes)", LAST[0])

# ---- A.13 LOW quantization, range 0..3.3 V: scale = 3.3 / 65534, offset 1.65, q clipped to +-32767 ----
Q_SCALE = 3.3 / 65534; Q_OFFSET = 1.65
def quantize(v):
    q = int(round((v - Q_OFFSET) / Q_SCALE)); clip = q > 32767 or q < -32767
    return max(-32767, min(32767, q)), clip
q_in = [0.00, 1.65, 3.30, 4.00]; q_out = [quantize(v) for v in q_in]
assert [q for q, _ in q_out] == [-32767, 0, 32767, 32767] and [c for _, c in q_out] == [False, False, False, True]
assert abs(Q_SCALE - 5.0356e-5) < 5e-9
_rec("t", "BRV_A13_SCALE", "A.13 LOW quantization scale (3.3 / 65534) and offset", "#define BRV_A13_SCALE_F %.9gf\n#define BRV_A13_OFFSET_F %.9gf" % (Q_SCALE, Q_OFFSET))
ei("BRV_A13_COUNT", "A.13 number of quantization cases", len(q_in))
_rec("t", "BRV_A13_VOLTS", "A.13 quantization inputs in volts", "static const float BRV_A13_VOLTS[BRV_A13_COUNT] = {%s};" % ", ".join("%.2ff" % v for v in q_in))
_rec("t", "BRV_A13_Q", "A.13 expected quantized values (clipped to +-32767)", "static const int16_t BRV_A13_Q[BRV_A13_COUNT] = {%s};" % ", ".join(str(q) for q, _ in q_out))
_rec("t", "BRV_A13_CLIP", "A.13 expected CLIP flag per case", "static const uint8_t BRV_A13_CLIP[BRV_A13_COUNT] = {%s};" % ", ".join("1" if c else "0" for _, c in q_out))

# ---- A.14 key bundle for node P: K_mesh(2) + pair key with S for epoch 2 ----
Kb = hkdf_expand(hkdf_extract(LBL_V1, K_node(P)), b"bundle", 16)
bundle_no = 3
tlvs = bytes([0x01, 33, 2]) + K_mesh(2) + bytes([0x02, 35]) + struct.pack("<HB", S, 2) + K_pair(S, P, 2)
bnonce = struct.pack("<BHI", 0x02, P, bundle_no) + bytes(6)
baad = b"PLB1" + struct.pack("<HI", P, bundle_no)
bct = AESCCM(Kb, tag_length=8).encrypt(bnonce, tlvs, baad)
bundle = struct.pack("<I", bundle_no) + bct
print("A.14 K_node(0042) = %s ; Kb = %s" % (K_node(P).hex(), Kb.hex()))
print("A.14 K_mesh(2) = %s" % K_mesh(2).hex()); print("A.14 K_pair(0042,1234,2) = %s" % K_pair(S, P, 2).hex())
print("A.14 bundle TLV plaintext (%d) = %s" % (len(tlvs), tlvs.hex()))
print("A.14 bundle nonce = %s ; AAD = %s" % (bnonce.hex(), baad.hex()))
print("A.14 bundle wire (%d) = %s" % (len(bundle), bundle.hex()))
assert AESCCM(Kb, tag_length=8).decrypt(bnonce, bct, baad) == tlvs
eb("BRV_A14_K_NODE_0042", "A.14 K_node(0042)", K_node(P))
eb("BRV_A14_KB", "A.14 Kb = Expand(Extract('%s', K_node), 'bundle', 16)" % LBL_V1.decode(), Kb)
eb("BRV_A14_K_MESH_2", "A.14 K_mesh(2)", K_mesh(2))
eb("BRV_A14_K_PAIR_0042_1234_2", "A.14 K_pair(0042, 1234, 2)", K_pair(S, P, 2))
eb("BRV_A14_TLVS", "A.14 bundle TLV plaintext (72 bytes)", tlvs)
ei("BRV_A14_BUNDLE_NO", "A.14 bundle_no", bundle_no)
eb("BRV_A14_NONCE", "A.14 bundle CCM nonce (13 bytes)", bnonce)
eb("BRV_A14_AAD", "A.14 bundle CCM AAD: 'PLB1' || node || bundle_no", baad)
eb("BRV_A14_BUNDLE_WIRE", "A.14 bundle wire (84 bytes) = bundle_no || ciphertext || tag", bundle)

# ---- J1: every session_id 0 frame type and RESUME must fit the smallest link, IR: 80 - 6 = 74 bytes ----
IR_PATH = 80 - 6
sizes = {"SEEK": 22 + 18 + 12 + 2, "HELLO": 19 + 28 + 12 + 2, "BIND": 19 + 17 + 12 + 2, "BIND_ACK": 19 + 12 + 12 + 2,
         "BIND_NAK": 19 + 9 + 12 + 2, "RESUME": 19 + 5 + 12 + 2, "RESUME_ACK": 19 + 6 + 12 + 2,
         "MGMT_REQ fixed": 19 + 22 + 12 + 2, "MGMT_RESP fixed + cmd TLV": 19 + 33 + 3 + 12 + 2}
for k, v in sizes.items():
    assert v <= IR_PATH, (k, v)
print("A.15 frame sizes with AUTH:", ", ".join("%s %d" % kv for kv in sizes.items()), "; all <= %d (IR)" % IR_PATH)
ei("BRV_A15_IR_PATH", "A.15 smallest link budget: 80 - 6", IR_PATH)
for _k, _v in sizes.items(): ei("BRV_A15_SIZE_" + _k.upper().replace(" + ", "_PLUS_").replace(" ", "_"), "A.15 frame size with AUTH: " + _k, _v)
# IR edge link: leaf L 0x0020 -> attached node A 0x0021, edge keys from K_pair(L, A, E_prov = 1)
L, A = 0x0020, 0x0021
prk_edge = hkdf_extract(LBL_V1, K_pair(L, A, 1))
K_hop_edge = hkdf_expand(prk_edge, b"edge-hop", 32); Ke_edge = hkdf_expand(prk_edge, b"edge-enc", 16)
print("A.15 K_pair(0020,0021,1) = %s" % K_pair(L, A, 1).hex())
print("A.15 K_hop_edge = %s ; Ke_edge = %s" % (K_hop_edge.hex(), Ke_edge.hex()))
eb("BRV_A15_K_PAIR_0020_0021_1", "A.15 K_pair(0020, 0021, 1)", K_pair(L, A, 1))
eb("BRV_A15_K_HOP_EDGE", "A.15 K_hop_edge = Expand(PRK_edge, 'edge-hop', 32)", K_hop_edge)
eb("BRV_A15_KE_EDGE", "A.15 Ke_edge = Expand(PRK_edge, 'edge-enc', 16)", Ke_edge)
pre_l = 0x00000011
lpay = struct.pack("<IIHHBBI", pre_l, 0x11223344, 0x001B, 80, 1, 0, 1)   # caps HIGH|LOW|AUTH|FEC (no RELAY), max_frame 80, key_epoch E_prov 1
hl = hdr(0x12, 0x01, L, A, L, A, 1, 0, 0x0100, 0, pre_l & 0xFFFF, len(lpay), 74, 0)   # edge: unicast to the one neighbour, ttl 1
_, ltag, _, _ = ccm(Ke_edge, hl, 0, pre_l >> 16, lpay, b"")
fl = frame(hl, lpay, ltag, K_hop_edge)
show("A.15 IR SEEK", fl)
eb("BRV_A15_SEEK_HEADER", "A.15 IR SEEK header (22 bytes), L -> A, ttl 1, hop_seq 0x100", hl)
eb("BRV_A15_SEEK_PAYLOAD", "A.15 IR SEEK clear payload (18 bytes)", lpay)
eb("BRV_A15_SEEK_CCM_TAG", "A.15 IR SEEK ccm_tag (empty plaintext, key Ke_edge, 8 bytes)", ltag)
ef("BRV_A15_SEEK", "A.15 IR SEEK full frame (54 bytes)", fl)
lpar = rs_encode(fl, 6); print("A.15 IR SEEK RS parity (6): %s ; on-air %d bytes" % (lpar.hex(), len(fl) + 6))
ei("BRV_A15_SEEK_RS_NSYM", "A.15 IR SEEK RS parity symbols", 6)
eb("BRV_A15_SEEK_RS_PARITY", "A.15 IR SEEK RS(6) parity over BRV_A15_SEEK_FRAME", lpar)
ei("BRV_A15_SEEK_ON_AIR_LEN", "A.15 IR SEEK on-air length (frame + parity)", len(fl) + 6)
T0e = hashlib.sha256(e2e(hl) + lpay).digest()
Ke_hello_e = hkdf_expand(prk_edge, b"hello" + struct.pack("<HH", L, A) + T0e, 16)
pre_a = 0x00000005
ea_secret = struct.pack("<IIIHHbBBBI", pre_l, 0x11223344, 0x55667788, 0x001B, 74, -128, 0, 20, 0, 1)   # rssi unknown on IR, path_cost 20
hha = hdr(0x12, 0x02, A, L, A, L, 1, 0, 0x0200, 0, pre_a & 0xFFFF, 4 + len(ea_secret))
abody, atag, _, _ = ccm(Ke_hello_e, hha, 1, pre_a >> 16, struct.pack("<I", pre_a), ea_secret)
fa = frame(hha, abody, atag, K_hop_edge)
show("A.15 IR HELLO", fa); assert len(fa) + 6 <= 80
print("A.15 IR HELLO RS parity (6): %s ; on-air %d bytes" % (rs_encode(fa, 6).hex(), len(fa) + 6))
eb("BRV_A15_T0_EDGE", "A.15 T0 = SHA-256(IR SEEK e2e header || payload)", T0e)
eb("BRV_A15_KE_HELLO_EDGE", "A.15 Ke_hello for the edge pair key", Ke_hello_e)
eb("BRV_A15_HELLO_HEADER", "A.15 IR HELLO header (19 bytes), A -> L", hha)
eb("BRV_A15_HELLO_CLEAR", "A.15 IR HELLO clear pre_ctr 5", struct.pack("<I", pre_a))
eb("BRV_A15_HELLO_SECRET", "A.15 IR HELLO secret plaintext (24 bytes), nonce_p 0x55667788, rssi -128, cost 20", ea_secret)
eb("BRV_A15_HELLO_PAYLOAD", "A.15 IR HELLO payload = clear pre_ctr || ciphertext", abody)
eb("BRV_A15_HELLO_TAG", "A.15 IR HELLO CCM tag (8 bytes)", atag)
ef("BRV_A15_HELLO", "A.15 IR HELLO full frame (61 bytes)", fa)
ei("BRV_A15_HELLO_RS_NSYM", "A.15 IR HELLO RS parity symbols", 6)
eb("BRV_A15_HELLO_RS_PARITY", "A.15 IR HELLO RS(6) parity over BRV_A15_HELLO_FRAME", rs_encode(fa, 6))
ei("BRV_A15_HELLO_ON_AIR_LEN", "A.15 IR HELLO on-air length (frame + parity)", len(fa) + 6)

def est_roc(seq, s_l, roc):
    if s_l < 32768: return roc - 1 if (seq - s_l) > 32768 else roc
    return roc + 1 if (s_l - 32768) > seq else roc
ROC_CASES = [(0x0005, 0xFFF0, 0, 1), (0xFFF0, 0x0005, 1, 0), (0x8001, 0x0000, 3, 2), (0x7FFF, 0xFFFF, 3, 3)]   # last = roc used (spec A.10)
for seq, s_l, roc, want in ROC_CASES:
    print("A.10 ROC: seq=0x%04X highest=0x%04X roc=%d -> %d" % (seq, s_l, roc, est_roc(seq, s_l, roc)))
    assert est_roc(seq, s_l, roc) == want
ei("BRV_A10_ROC_CASE_COUNT", "A.10 number of ROC estimation cases", len(ROC_CASES))
_rec("t", "BRV_A10_ROC_CASES", "A.10 ROC estimation cases: (seq, highest, roc) -> roc used",
     "typedef struct { uint16_t seq; uint16_t highest; uint32_t roc; uint32_t expected; } brv_roc_case_t;\n"
     "static const brv_roc_case_t BRV_A10_ROC_CASES[BRV_A10_ROC_CASE_COUNT] = {\n%s\n};" % ",\n".join("    { 0x%04Xu, 0x%04Xu, %du, %du }" % c for c in ROC_CASES))
assert AESCCM(Ke_s2p, tag_length=8).decrypt(dn, dbody + dtag, da) == dpay
assert AESCCM(K_mgmt, tag_length=8).decrypt(gn, gbody[4:] + gtag, ga) == g_secret

# ---- Markdown emitter: the PROTOCOL.md Appendix A body (A.1 .. A.15), written only with --emit-md PATH ----
def write_md_appendix(path):
    def sp(b): return " ".join("%02x" % x for x in b)
    def cr(f): return "0x%04X" % crc16(f[:-2])
    v1 = LBL_V1.decode()
    f2 = frame(h2, seek_pay)
    fd1 = frame(hd1, dbody, dtag, K_hop(1)); fd2 = frame(hd2, dbody, dtag, K_hop(1)); fd2k0 = frame(hd2, dbody, dtag, K_hop(0))
    fs1 = frame(hs1, spay, stag, K_hop(1)); fs2 = frame(hs2, spay, stag, K_hop(1))
    fh = frame(hh, hbody, htag, K_hop(1)); fb = frame(hb, bbody, btag, K_hop(1)); fr = frame(hd_r, rbody, rtag, K_hop(1))
    fres = frame(hr, rpay, rtg, K_hop(1)); fmq = frame(hm, mbody, mtag, K_hop(1)); fmr = frame(hg, gbody, gtag, K_hop(1))
    roc = "; ".join("(0x%04X, 0x%04X, %d) -> %d" % c for c in ROC_CASES[:2]) + ";\n" + \
          "; ".join("(0x%04X, 0x%04X, %d) -> %d" % c for c in ROC_CASES[2:])
    qs = [q for q, _ in q_out]
    wire_hex = bundle.hex()
    md = f"""A.1 CRC-16/CCITT-FALSE: `"123456789"` -> 0x{crc16(b"123456789"):04X}

A.2 SEEK on ESP-NOW, bench profile (no tags)

```
prev 0x1234, next 0xFFFF, ttl 4 / hops 0, hop_seq 1, path_mtu 250, path_cost 0, session 0, seq 1;
payload: pre_ctr 1, nonce_s 0xA1B2C3D4, caps 0x0033 (HIGH|LOW|FEC|RELAY), max_frame 250, epoch 0, minor 0, fw 1
{sp(h2)}
{sp(seek_pay)}  {sp(f2[-2:])}            {len(f2)} bytes, CRC16 = {cr(f2)}
```

A.3 Same SEEK on UART: path_mtu 242, RS nsym 8, then COBS

```
frame ({len(f3)}): as A.2 with {sp(h3[15:17])} at offset 15 and CRC {sp(f3[-2:])} ({cr(f3)})
RS parity:  {sp(par)}
COBS wire ({len(wire)}): {sp(wire[:31])}
                {sp(wire[31:])}
```

A.4 RS standalone: RS(6) of "{rs4a.decode()}" = {sp(rs_encode(rs4a, 6))}; RS(1) of {sp(rs4b)} = {sp(rs_encode(rs4b, 1))} (= XOR)

A.5 Cross-frame FEC (unchanged since v0.2): k 2 / m 1 blocks `{sp(fa_blocks[0])}`, `{sp(fa_blocks[1])}`
-> parity `{sp(fa_par[0])}`; k 4 / m 2 blocks {", ".join("`%s`" % sp(b) for b in fb_blocks)}
-> parity `{sp(fb_par[0])}`, `{sp(fb_par[1])}`; erasure-decoding with positions {{1, 3}} reproduces blocks 1 and 3.

A.6 Keys (K_site TEST ONLY = bytes 0x00..0x1F)

```
K_mesh(1)  = {K_mesh(1).hex()}
K_hop(1)   = {K_hop(1).hex()}
K_hop(0)   = {K_hop(0).hex()}
Ke_mesh(1) = {Ke_mesh(1).hex()}
K_pair(0042, 1234, 1) = {K_pair(S, P, 1).hex()}
PRK = Extract("{v1}", K_pair) = {PRK.hex()}
```

A.7 DATA on a direct link (Ke_s2p from A.9), session 7, seq 5, ROC 0, hop_seq 9, one float32 1.5 at t = 1000 us

```
header: {sp(hd)}
plaintext = {sp(dpay)} ; nonce = {sp(dn)}
AAD = {sp(da)} ; ciphertext = {sp(dbody)}
ccm_tag = {sp(dtag)} ; hop_tag = HMAC(K_hop(1), frame[0..37])[0..3] = {sp(fd[-6:-2])}
frame ({len(fd)}): header || ciphertext || ccm_tag || {sp(fd[-6:-2])} || {sp(fd[-2:])}              CRC16 = {cr(fd)}
```

A.8 Two hops: the A.7 frame via R, and a keyed SEEK flood

```
DATA hop 1 (S -> R): prev 0x1234, next 0x0099, ttl 4 / hops 0, hop_seq 9
{sp(fd1[:30])}
{sp(fd1[30:])}                                       CRC16 = {cr(fd1)}
DATA hop 2 (R -> P): prev 0x0099, next 0x0042, ttl 3 / hops 1, hop_seq 0x00010131
{sp(fd2[:30])}
{sp(fd2[30:])}                                       CRC16 = {cr(fd2)}
Same hop 2 re-tagged under epoch 0 (R replying to a neighbour it last verified under 0, 8.5):
hop_tag {sp(fd2k0[-6:-2])}, CRC16 = {cr(fd2k0)}

SEEK, field profile: pre_ctr 0x00010001 (header seq 0x0001), caps 0x003B (HIGH|LOW|AUTH|FEC|RELAY), key_epoch 1
payload (clear) = {sp(spay)}
nonce = {sp(sn)} ; AAD = e2e header || {sp(struct.pack("<I", pre_s >> 16))} || payload
ccm_tag (over empty plaintext, Ke_mesh(1)) = {sp(stag)}
hop 1 (S, hop_seq 7, path_mtu 250, cost 0) ({len(fs1)}):
{sp(fs1[:34])}
{sp(fs1[34:])}                      CRC16 = {cr(fs1)}
hop 2 (R, hop_seq 0x00010130, ttl 3 / hops 1, path_mtu 250, cost 1) ({len(fs2)}):
{sp(fs2[:34])}
{sp(fs2[34:])}                      CRC16 = {cr(fs2)}
```

A.9 Handshake keys, HELLO (pre_ctr above 0x10000) and BIND

```
T0 = SHA-256(SEEK e2e header || SEEK payload) = {T0.hex()}
Ke_hello = Expand(PRK, "hello" || 34 12 || 42 00 || T0, 16) = {Ke_hello.hex()}
HELLO (P -> S via R): header {sp(hh)}, pre_ctr 0x{pre_p:08X}
clear = {sp(h_clear)} ; secret plaintext = {sp(h_secret)}
        (seek_ctr 0x00010001, nonce_s, nonce_p 0x0BADF00D, caps, max_frame 250, rssi -61, status 0, cost 1, minor 0, fw 2)
nonce = {sp(hn)} ; AAD = {sp(ha)}
payload = {sp(hbody)} ; tag = {sp(htag)}
frame ({len(fh)}): header || payload || tag || hop_tag {sp(fh[-6:-2])} || {sp(fh[-2:])}                 CRC16 = {cr(fh)}
T  = SHA-256(SEEK e2e || SEEK payload || HELLO e2e || HELLO plaintext payload) = {T.hex()}
Ke_hs = {Ke_hs.hex()} ; Ke_s2p = {Ke_s2p.hex()} ; Ke_p2s = {Ke_p2s.hex()}
BIND (S -> P via R): header {sp(hb)}, pre_ctr 0x{pre_b:08X}
clear = {sp(b_clear)} ; secret = {sp(b_secret)} (hello_ctr, nonces, session 7)
nonce = {sp(bn)} ; payload = {sp(bbody)}
tag = {sp(btag)} ; frame ({len(fb)}): header || payload || tag || hop_tag {sp(fb[-6:-2])} || {sp(fb[-2:])}   CRC16 = {cr(fb)}
```

A.10 ROC: estimation cases and a second-cycle frame

```
(seq, highest, roc) -> roc used: {roc}
A.7 plaintext at ROC 1, seq 5, hop_seq 0x2345: nonce {sp(rn)}
ciphertext = {sp(rbody)} ; tag = {sp(rtag)}
frame ({len(fr)}): {sp(fr[:30])}
            {sp(fr[30:])}                           CRC16 = {cr(fr)}
```

A.11 RESUME flood (clear, Ke_s2p), session 7 at seq 0x0042, ROC 0, pre_ctr 0x00010003, ttl 3, hop_seq 0x4000

```
header {sp(hr)} ; payload {sp(rpay)}
nonce = {sp(rnn)} ; ccm_tag = {sp(rtg)}
frame ({len(fres)}): header || payload || tag || hop_tag {sp(fres[-6:-2])} || {sp(fres[-2:])}                  CRC16 = {cr(fres)}
```

A.12 MGMT_REQ (flooded, no route) from P and the MGMT_RESP from M

```
K_pair(0001, 0042, 1) = {K_pair(P, M, 1).hex()}
K_mgmt(0042 -> 0001) = Expand(Extract("{v1}", K_pair), "mgmt" || 42 00 || 01 00, 16) = {K_mgmt.hex()}
MGMT_REQ: header {sp(hm)}, pre_ctr 0x{pre_m:08X}
secret = {sp(m_secret)}
         (t1 123456789, e_new 1, e_old 1, flags 0, section 0, page 0, chunk 0, bundle_no 3, then 8 illustrative report bytes;
          a real section 0 is 38 bytes)
nonce = {sp(mn)}
payload = {sp(mbody)}
tag = {sp(mtag)} ; frame ({len(fmq)}): header || payload || tag || hop_tag {sp(fmq[-6:-2])} || {sp(fmq[-2:])}   CRC16 = {cr(fmq)}
MGMT_RESP: header {sp(hg)}, pre_ctr 0x{pre_g:08X}
secret = {sp(g_secret)}
         (req_ctr 0x00010008, t1 echo, t2 1700000000000000, t3 1700000000000500, flags 0)
nonce = {sp(gn)}
payload = {sp(gbody)}
tag = {sp(gtag)} ; frame ({len(fmr)}): header || payload || tag || hop_tag {sp(fmr[-6:-2])} || {sp(fmr[-2:])}   CRC16 = {cr(fmr)}
```

A.13 LOW quantization, range 0..3.3 V: scale 5.0356e-5, offset 1.65; v 0.00 -> q {qs[0]}; 1.65 -> {qs[1]};
3.30 -> {qs[2]}; 4.00 -> {qs[3]} with CLIP.

A.14 Key bundle for node P (illustrative two-TLV snapshot: epoch 2 only, so applying it retires epoch 1; a real snapshot lists every peer, this one would revoke all but S)

```
K_node(0042) = {K_node(P).hex()}
Kb = Expand(Extract("{v1}", K_node), "bundle", 16) = {Kb.hex()}
K_mesh(2) = {K_mesh(2).hex()}
K_pair(0042, 1234, 2) = {K_pair(S, P, 2).hex()}
TLVs ({len(tlvs)}) = 01 21 02 <K_mesh(2)> 02 23 34 12 02 <K_pair(0042,1234,2)>
bundle_no {bundle_no} ; nonce = {sp(bnonce)} ; AAD = {sp(baad)}
bundle wire ({len(bundle)}) = {sp(bundle[:4])} || ciphertext ({len(tlvs)}) || tag:
{wire_hex[:104]}
{wire_hex[104:]}
```

A.15 IR edge link: frame budget and edge-key SEEK / HELLO (leaf L 0x0020, attached node A 0x0021, E_prov 1)

```
Sizes with AUTH: SEEK {sizes["SEEK"]}, HELLO {sizes["HELLO"]}, BIND {sizes["BIND"]}, BIND_ACK {sizes["BIND_ACK"]}, BIND_NAK {sizes["BIND_NAK"]}, RESUME {sizes["RESUME"]}, RESUME_ACK {sizes["RESUME_ACK"]},
MGMT_REQ fixed {sizes["MGMT_REQ fixed"]}, MGMT_RESP fixed + one command TLV {sizes["MGMT_RESP fixed + cmd TLV"]}; all <= {IR_PATH} = 80 - 6 (the script asserts this).
K_pair(0020, 0021, 1) = {K_pair(L, A, 1).hex()}
K_hop_edge = {K_hop_edge.hex()} ; Ke_edge = {Ke_edge.hex()}
SEEK (L -> A, unicast on the edge, ttl 1, hop_seq 0x100, path_mtu 74, pre_ctr 0x11, caps HIGH|LOW|AUTH|FEC, max_frame 80, key_epoch 1):
{sp(fl[:40])}
{sp(fl[40:])}                                        {len(fl)} bytes, CRC16 = {cr(fl)}
RS parity (6): {sp(lpar)} ; on the air {len(fl) + 6} bytes
HELLO (A -> L, pre_ctr 5, nonce_p 0x55667788, rssi -128 unknown, status 0, path_cost 20, fw 1; Ke_hello from PRK of the edge pair key and T0):
{sp(fa[:50])}
{sp(fa[50:])}                                                 {len(fa)} bytes, CRC16 = {cr(fa)}
RS parity (6): {sp(rs_encode(fa, 6))} ; on the air {len(fa) + 6} bytes
```
"""
    assert all(ord(c) < 128 for c in md)
    with open(path, "w") as fh_: fh_.write(md)

# ---- field-profile test-key blacklist (spec 12.1): SHA-256(K_mesh(E))[0..7] for E = 0..255 ----
KMESH_HASH8_DECL = "static const uint8_t s_test_kmesh_hash8[256][8] = {"
def kmesh_hash8_rows():
    return ["    {%s}, /* E %d */" % (", ".join("0x%02x" % b for b in hashlib.sha256(K_mesh(E)).digest()[:8]), E) for E in range(256)]
def splice_kmesh_hash8(path):
    """rewrite the s_test_kmesh_hash8 initializer in place in br_crypto.c (everything else untouched)"""
    with open(path) as fh_: lines = fh_.read().split("\n")
    i = lines.index(KMESH_HASH8_DECL); j = lines.index("};", i)
    out = "\n".join(lines[:i + 1] + kmesh_hash8_rows() + lines[j:])
    assert all(ord(c) < 128 for c in out)
    with open(path, "w") as fh_: fh_.write(out)

print("ALL OK")
if "--emit-c" in sys.argv:
    write_c_header(sys.argv[sys.argv.index("--emit-c") + 1])
if "--emit-md" in sys.argv:
    write_md_appendix(sys.argv[sys.argv.index("--emit-md") + 1])
if "--emit-kmesh-hash8" in sys.argv:
    splice_kmesh_hash8(sys.argv[sys.argv.index("--emit-kmesh-hash8") + 1])
