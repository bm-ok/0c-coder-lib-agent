import binascii
import hashlib
import struct
import types

import ecdsa
import pytest

from ... import formats, util
from .. import agent, client, keyring, protocol


def test_sig_encode():
    SIG = (
        b'(7:sig-val(5:ecdsa(1:r32:\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        b'\x00\x00\x00\x00\x0c)(1:s32:\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        b'\x00\x00\x00\x00")))')
    assert agent.sig_encode(12, 34) == SIG


CREATED = 1500000000  # arbitrary, fixed so that key IDs are reproducible
USER_ID_FIRST = 'First User <first@example.com>'
USER_ID_SECOND = 'Second User <second@example.com>'
USER_ID_OTHER = 'Nobody <nobody@example.com>'
USER_ID_THIRD = 'Third User <third@example.com>'
# OpenPGP user IDs are supposed to be UTF-8, but GnuPG does not enforce it and
# Latin-1 user IDs exist in the wild.
USER_ID_LATIN1 = b'Jos\xe9 <jose@example.com>'
RSA_ALGO_ID = 1  # RSA (Encrypt or Sign), rfc4880 section-9.1
RSA_EXPONENT = 65537


def _derive(identity):
    """Derive a distinct NIST256 key per identity, the way a device would."""
    # The device hashes Identity.to_bytes() - which does NOT include the
    # keygrip - so the user ID alone decides which key comes back.
    secexp = util.bytes2num(hashlib.sha256(identity.to_bytes()).digest())
    return ecdsa.SigningKey.from_secret_exponent(
        secexp=secexp, curve=ecdsa.curves.NIST256p,
        hashfunc=hashlib.sha256).get_verifying_key()


def _derive_modulus(identity):
    """Derive a distinct 2048-bit RSA modulus per identity."""
    seed = hashlib.sha256(identity.to_bytes()).digest()
    blob = b''.join(hashlib.sha256(seed + bytes([i])).digest() for i in range(8))
    # Set the top bit, so that the modulus is exactly 2048 bits long and
    # protocol.keygrip_rsa() serializes it to 256 bytes on both sides.
    return bytes([blob[0] | 0x80]) + blob[1:]


class FakeDevice:
    """Device that derives keys in-process, without any hardware."""

    def __init__(self):
        """C-tor."""
        self.ui = types.SimpleNamespace(options_getter=None)
        self.user_ids = []

    def __enter__(self):
        """Allow usage as context manager."""
        return self

    def __exit__(self, *args):
        """Nothing to close."""

    def pubkey(self, identity, ecdh=False):  # pylint: disable=unused-argument
        """Return the public key derived for this identity."""
        self.user_ids.append(identity.identity_dict['host'])
        if identity.curve_name in ('rsa2048', 'rsa4096'):
            # onlykey.py returns the raw modulus bytes for RSA, not a key
            # object - see its pubkey(), the non-'ssh' proto branch.
            return _derive_modulus(identity)
        return _derive(identity)


def _encode_user_id(user_id):
    """Serialize a user ID, which may be given as raw (non-UTF-8) bytes."""
    return user_id if isinstance(user_id, bytes) else user_id.encode('utf-8')


def _public_key_blob(derived_from, user_ids):
    """Serialize a public key packet, followed by several user ID packets."""
    identity = client.create_identity(user_id=derived_from,
                                      curve_name=formats.CURVE_NIST256)
    pubkey = protocol.PublicKey(curve_name=formats.CURVE_NIST256,
                                created=CREATED,
                                verifying_key=_derive(identity))
    blob = protocol.packet(tag=6, blob=pubkey.data())
    for user_id in user_ids:
        blob += protocol.packet(tag=13, blob=_encode_user_id(user_id))
    return binascii.hexlify(pubkey.keygrip()).upper(), blob


def _rsa_public_key_blob(derived_from, user_ids):
    """Serialize an RSA-2048 public key packet, then the user ID packets."""
    identity = client.create_identity(user_id=derived_from,
                                      curve_name='rsa2048')
    modulus = util.bytes2num(_derive_modulus(identity))
    # v4 public key packet: version, creation time, algo, MPI(n), MPI(e).
    data = (struct.pack('>BLB', 4, CREATED, RSA_ALGO_ID) +
            protocol.mpi(modulus) + protocol.mpi(RSA_EXPONENT))
    blob = protocol.packet(tag=6, blob=data)
    for user_id in user_ids:
        blob += protocol.packet(tag=13, blob=_encode_user_id(user_id))
    keygrip = protocol.keygrip_rsa(modulus, modulus.bit_length())
    return binascii.hexlify(keygrip).upper(), blob


def _handler(monkeypatch, pubkey_bytes):
    monkeypatch.setattr(keyring, 'gpg_version', lambda: b'2.2.0')
    return agent.Handler(device=FakeDevice(), pubkey_bytes=pubkey_bytes)


def test_get_identity_uses_user_id_matching_keygrip(monkeypatch):
    # The key belongs to the SECOND user ID of a two-user-ID public key.
    keygrip, pubkey_bytes = _public_key_blob(
        derived_from=USER_ID_SECOND,
        user_ids=[USER_ID_FIRST, USER_ID_SECOND])
    handler = _handler(monkeypatch, pubkey_bytes)
    identity = handler.get_identity(keygrip=keygrip)
    assert identity.identity_dict['host'] == USER_ID_SECOND
    assert handler.client.device.user_ids == [USER_ID_FIRST, USER_ID_SECOND]


def test_get_identity_without_matching_user_id(monkeypatch):
    # No user ID of the key re-derives it, so the keygrip must be reported as
    # missing (KeyError) - which is what have_key() and GnuPG can act upon.
    keygrip, pubkey_bytes = _public_key_blob(
        derived_from=USER_ID_OTHER,
        user_ids=[USER_ID_FIRST, USER_ID_SECOND])
    handler = _handler(monkeypatch, pubkey_bytes)
    with pytest.raises(KeyError):
        handler.get_identity(keygrip=keygrip)


def test_get_identity_skips_non_utf8_user_id(monkeypatch):
    # A user ID that cannot be decoded is not a candidate, but it must not end
    # the search either - the user ID that does derive the key comes after it.
    keygrip, pubkey_bytes = _public_key_blob(
        derived_from=USER_ID_THIRD,
        user_ids=[USER_ID_LATIN1, USER_ID_THIRD])
    handler = _handler(monkeypatch, pubkey_bytes)
    identity = handler.get_identity(keygrip=keygrip)
    assert identity.identity_dict['host'] == USER_ID_THIRD
    # Skipped before the device was asked, rather than derived from a mangled
    # string that could never have matched anyway.
    assert handler.client.device.user_ids == [USER_ID_THIRD]


def test_get_identity_rsa_uses_user_id_matching_keygrip(monkeypatch):
    # Same as the first test but for an RSA key, which takes the other half of
    # _derive_identity(): no key ID to compare, so the modulus the device
    # returns is checked against the keygrip decode.py computed.
    keygrip, pubkey_bytes = _rsa_public_key_blob(
        derived_from=USER_ID_SECOND,
        user_ids=[USER_ID_FIRST, USER_ID_SECOND])
    handler = _handler(monkeypatch, pubkey_bytes)
    identity = handler.get_identity(keygrip=keygrip)
    assert identity.identity_dict['host'] == USER_ID_SECOND
    # Proves the RSA half ran: the ECC half never yields these curve names.
    assert identity.curve_name == 'rsa2048'
    assert handler.client.device.user_ids == [USER_ID_FIRST, USER_ID_SECOND]
