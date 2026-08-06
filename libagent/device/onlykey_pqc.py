"""
libagent/device/onlykey_pqc.py — composite post-quantum PGP for the OnlyKey backend.

Bridges lib-agent's GPG sign/decrypt to the composite PQC keys loaded on the OnlyKey
(trustcrypto/libraries PR #31). One RSA slot (1-4) holds the composite key; the device
does each half on-device, the host does the OpenPGP composite framing (concat sig /
SHA3-256 key combine + AES key-unwrap), exactly like the openpgp.js `pqc` branch.

Composite algorithms (draft-ietf-openpgp-pqc):
  * pqc_mldsa_ed25519 (algo 30): sign = Ed25519 sig (64) || ML-DSA-65 sig (3309)
  * pqc_mlkem_x25519  (algo 35): decrypt = X25519 + ML-KEM-768, combined with
    SHA3-256 over the two key shares plus "OpenPGPCompositeKDFv1" and its
    length (draft-ietf-openpgp-pqc-10), then RFC 3394 AES-256 key-unwrap.

Wire protocol (okpqc.cpp on the device):
  * OKSIGN,    slot, payload = [selector] + digest      (selector 0=Ed25519, 1=ML-DSA)
  * OKDECRYPT, slot, payload = 32-B X25519 point  -> 32-B shared secret (ECC half)
  * OKDECRYPT, slot, payload = 1088-B ML-KEM ct   -> 32-B shared secret (PQC half)

UNTESTED against hardware — by inspection; mirror-verified against openpgp.js kem.js.
No shipping GnuPG can consume these keys: GnuPG is on the LibrePGP track (v5 keys,
its own Kyber codepoint 8, no ML-DSA at all) and cannot parse a v6 key packet.
rpgp >= 0.20 with the `draft-pqc` feature is the interoperable implementation.
"""
import hashlib
import struct

# component selectors (match okpqc.h)
HALF_ECC = 0
HALF_PQC = 1

# sizes
X25519_PT_LEN = 32
MLKEM_CT_LEN  = 1088
SS_LEN        = 32
ED25519_SIG_LEN = 64
MLDSA_SIG_LEN   = 3309

# IANA-assigned (draft-ietf-openpgp-pqc-10). This is NOT just a tag: it is an
# input to the key combiner in composite_decrypt() below, so it is bound into
# the derived KEK. It was 105 - a PRIVATE/experimental codepoint - and every key
# or message produced under that value is unreadable here and everywhere else.
MLKEM_ALGO_ID = 35   # pqc_mlkem_x25519
COMPOSITE_KDF_LABEL = b"OpenPGPCompositeKDFv1"


# --------------------------- device dual-ops ---------------------------------

def _read_exact(ok, want, timeout_s=22):
    import time
    out = bytearray()
    t_end = time.time() + timeout_s
    while time.time() < t_end and len(out) < want:
        try:
            part = ok.read_bytes(timeout_ms=100)
        except Exception:
            continue
        if part:
            out.extend(part)
    return bytes(out[:want])


def device_sign_half(ok, slot, selector, digest):
    """OKSIGN one half. Returns the raw signature (64 B Ed25519 / 3309 B ML-DSA)."""
    ok.send_large_message2(msg=ok_msg(ok, 'OKSIGN'), slot_id=slot,
                           payload=bytes([selector]) + bytes(digest))
    want = ED25519_SIG_LEN if selector == HALF_ECC else MLDSA_SIG_LEN
    return _read_exact(ok, want)


def device_decap_half(ok, slot, data):
    """OKDECRYPT one half. `data` is the 32-B X25519 point or the 1088-B ML-KEM ct;
    the device selects by size and returns the 32-B shared secret."""
    ok.send_large_message2(msg=ok_msg(ok, 'OKDECRYPT'), slot_id=slot, payload=bytes(data))
    return _read_exact(ok, SS_LEN)


def ok_msg(ok, name):
    """Resolve the Message enum from whatever onlykey client the backend holds."""
    from onlykey.client import Message
    return getattr(Message, name)


# --------------------------- composite sign ----------------------------------

def composite_sign(ok, slot, digest):
    """pqc_mldsa_ed25519 signature = Ed25519(64) || ML-DSA-65(3309)."""
    ecc = device_sign_half(ok, slot, HALF_ECC, digest)
    pqc = device_sign_half(ok, slot, HALF_PQC, digest)
    if len(ecc) != ED25519_SIG_LEN or len(pqc) != MLDSA_SIG_LEN:
        raise ValueError("composite sign: bad half lengths %d/%d" % (len(ecc), len(pqc)))
    return ecc + pqc


# --------------------------- composite decrypt -------------------------------

def _sha3_256(*parts):
    h = hashlib.sha3_256()
    for p in parts:
        h.update(p)
    return h.digest()


def kmac256(key, data, out_len, custom=b""):
    """KMAC256(key, data, out_len, custom) per NIST SP 800-185.

    NO LONGER USED by the key combiner. Kept because it is the only KMAC256
    binding in this tree and deleting it would make the diff that removed it
    look like the KDF change rather than a tidy-up; the combiner moved to plain
    SHA3-256 in draft-ietf-openpgp-pqc-10. Remove it whenever, separately.

    Backed by pycryptodome (Crypto.Hash.KMAC256); the customization string S is
    what carried the "OpenPGPCompositeKDFv1" domain separation.
    """
    from Crypto.Hash import KMAC256  # pip install pycryptodome
    return KMAC256.new(key=bytes(key), data=bytes(data), mac_len=out_len,
                       custom=bytes(custom)).digest()


def _aes_key_unwrap(kek, wrapped):
    """RFC 3394 AES key unwrap (AES-256)."""
    from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
    return aes_key_unwrap(bytes(kek), bytes(wrapped))


def composite_decrypt(ok, slot, ecc_ct, mlkem_ct, ecc_pub, mlkem_pub, wrapped_key,
                      algo_id=MLKEM_ALGO_ID):
    """pqc_mlkem_x25519 decrypt -> session key.

    ecc_ct: 32-B X25519 ephemeral point; mlkem_ct: 1088-B ML-KEM ciphertext;
    ecc_pub: 32-B recipient X25519 pubkey; mlkem_pub: 1184-B ML-KEM ek; wrapped_key: C.
    Mirrors openpgp.js kem.js decrypt exactly.
    """
    # 1) device does both halves
    ecc_ss   = device_decap_half(ok, slot, ecc_ct)      # X25519(k, ephemeral)
    mlkem_ss = device_decap_half(ok, slot, mlkem_ct)    # ML-KEM decapsulate

    # 2) ECC key share IS the raw X25519 shared secret (draft-10, "X25519 KEM").
    #    An earlier draft revision hashed it with the ciphertext and the
    #    recipient key; that extra SHA3-256 was one of two reasons this stack's
    #    KEK differed from every conforming implementation's.
    ecc_key_share = ecc_ss
    mlkem_key_share = mlkem_ss

    # 3) Key combiner (draft-10):
    #      SHA3-256( mlkemKeyShare || ecdhKeyShare || ecdhCipherText ||
    #                ecdhPublicKey || algId || domSep || len(domSep) )
    #
    #    Was KMAC256 keyed on the two shares, over an encData that also carried
    #    mlkem_ct and mlkem_pub, with the label as the KMAC customization
    #    string. Neither the ML-KEM ciphertext nor its public key is an input
    #    any more.
    kek = _sha3_256(
        mlkem_key_share,
        ecc_key_share,
        ecc_ct,
        ecc_pub,
        bytes([algo_id]),
        COMPOSITE_KDF_LABEL,
        bytes([len(COMPOSITE_KDF_LABEL)]),
    )

    # 4) AES-256 key unwrap -> session key
    return _aes_key_unwrap(kek, wrapped_key)
