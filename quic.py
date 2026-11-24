"""Decrypt QUIC (HTTP/3) Initial packets the same way anyone on the path can.

QUIC Initial packets are "encrypted", but the keys are derived from the
Destination Connection ID that is sent in the clear, so your ISP can read the
TLS ClientHello inside them (and with it the website name) just like plain TLS.
"""
import hashlib
import hmac
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

QUIC_V1 = 0x00000001
QUIC_V2 = 0x6B3343CF

_SALTS = {
    QUIC_V1: bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),
    QUIC_V2: bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9"),
}
_INITIAL_TYPE = {QUIC_V1: 0, QUIC_V2: 1}
_LABEL_PREFIX = {QUIC_V1: b"quic ", QUIC_V2: b"quicv2 "}

_key_cache = {}


def varint(b, p):
    first = b[p]
    length = 1 << (first >> 6)
    val = first & 0x3F
    for i in range(1, length):
        val = (val << 8) | b[p + i]
    return val, p + length


def _expand_label(secret, label, length):
    full = b"tls13 " + label
    info = struct.pack(">HB", length, len(full)) + full + b"\x00"
    return hmac.new(secret, info + b"\x01", hashlib.sha256).digest()[:length]


def _keys(dcid, ver):
    ck = (dcid, ver)
    k = _key_cache.get(ck)
    if k is None:
        initial = hmac.new(_SALTS[ver], dcid, hashlib.sha256).digest()
        client = _expand_label(initial, b"client in", 32)
        pre = _LABEL_PREFIX[ver]
        k = (
            AESGCM(_expand_label(client, pre + b"key", 16)),
            _expand_label(client, pre + b"iv", 12),
            Cipher(algorithms.AES(_expand_label(client, pre + b"hp", 16)), modes.ECB()),
        )
        if len(_key_cache) > 2000:
            _key_cache.clear()
        _key_cache[ck] = k
    return k


def is_long_header_initial(dgram):
    if len(dgram) < 7 or not dgram[0] & 0x80:
        return False
    ver = struct.unpack_from(">I", dgram, 1)[0]
    return ver in _SALTS and ((dgram[0] >> 4) & 3) == _INITIAL_TYPE[ver]


def decrypt_initials(dgram):
    """Yield (dcid, plaintext) for every client Initial packet in a UDP datagram."""
    off = 0
    n = len(dgram)
    while off + 7 <= n and dgram[off] & 0x80:
        b0 = dgram[off]
        ver = struct.unpack_from(">I", dgram, off + 1)[0]
        if ver not in _SALTS:
            return
        p = off + 5
        dl = dgram[p]
        dcid = bytes(dgram[p + 1:p + 1 + dl])
        p += 1 + dl
        sl = dgram[p]
        p += 1 + sl
        ptype = (b0 >> 4) & 3
        if ptype == _INITIAL_TYPE[ver]:
            tl, p = varint(dgram, p)
            p += tl
        length, p = varint(dgram, p)
        pn_off = p
        end = pn_off + length
        if ptype != _INITIAL_TYPE[ver]:
            off = end  # coalesced 0-RTT/Handshake packet: skip it
            continue
        sample = bytes(dgram[pn_off + 4:pn_off + 20])
        if len(sample) < 16 or end > n:
            return
        aead, iv, hp = _keys(dcid, ver)
        mask = hp.encryptor().update(sample)
        first = b0 ^ (mask[0] & 0x0F)
        pnl = (first & 3) + 1
        hdr = bytearray(dgram[off:pn_off + pnl])
        hdr[0] = first
        base = pn_off - off
        for i in range(pnl):
            hdr[base + i] ^= mask[1 + i]
        pn = int.from_bytes(hdr[base:base + pnl], "big")
        nonce = bytes(a ^ b for a, b in zip(iv, pn.to_bytes(12, "big")))
        try:
            pt = aead.decrypt(nonce, bytes(dgram[pn_off + pnl:end]), bytes(hdr))
        except (InvalidTag, ValueError):
            return  # not decryptable with the original-DCID keys (e.g. later packets)
        yield dcid, pt
        off = end


def crypto_frames(pt):
    """Return [(offset, data)] for CRYPTO frames in a decrypted Initial payload."""
    out = []
    p = 0
    n = len(pt)
    try:
        while p < n:
            t = pt[p]
            if t in (0x00, 0x01):  # PADDING, PING
                p += 1
            elif t in (0x02, 0x03):  # ACK
                p += 1
                _, p = varint(pt, p)
                _, p = varint(pt, p)
                cnt, p = varint(pt, p)
                _, p = varint(pt, p)
                for _ in range(cnt):
                    _, p = varint(pt, p)
                    _, p = varint(pt, p)
                if t == 0x03:
                    for _ in range(3):
                        _, p = varint(pt, p)
            elif t == 0x06:  # CRYPTO
                p += 1
                o, p = varint(pt, p)
                ln, p = varint(pt, p)
                out.append((o, bytes(pt[p:p + ln])))
                p += ln
            else:
                break
    except IndexError:
        pass
    return out
