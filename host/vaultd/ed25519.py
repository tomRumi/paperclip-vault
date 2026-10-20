"""Ed25519 signature verification (RFC 8032, section 5.1.7), pure Python, stdlib only.

vaultd verifies the plugin's signatures without an openssl subprocess (the unit has no network and a tight
syscall filter). Verification handles public input only, so the variable-time arithmetic is not a leak.
Strict about encodings: S must be < L, both points must decode on the curve, and neither the public key nor R may have
small order (otherwise the identity key verifies a forged signature). Nothing here signs.
"""
import base64
import hashlib

P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
_SQRT_M1 = pow(2, (P - 1) // 4, P)
# DER prefix of a SubjectPublicKeyInfo holding a raw 32-byte Ed25519 key (what node:crypto exports)
SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


def _recover_x(y, sign):
    if y >= P:
        return None
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P:
        x = x * _SQRT_M1 % P
    if (x * x - x2) % P:
        return None
    return P - x if (x & 1) != sign else x


def _point(y, x):
    return (x, y, 1, x * y % P)


_BY = 4 * pow(5, P - 2, P) % P
BASE = _point(_BY, _recover_x(_BY, 0))
_ZERO = (0, 1, 1, 0)


def _add(p, q):
    a = (p[1] - p[0]) * (q[1] - q[0]) % P
    b = (p[1] + p[0]) * (q[1] + q[0]) % P
    c = 2 * p[3] * q[3] * D % P
    d = 2 * p[2] * q[2] % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def mul(s, p):
    q = _ZERO
    while s:
        if s & 1:
            q = _add(q, p)
        p = _add(p, p)
        s >>= 1
    return q


def encode(p):
    zi = pow(p[2], P - 2, P)
    x, y = p[0] * zi % P, p[1] * zi % P
    return (y | (x & 1) << 255).to_bytes(32, "little")


def decode(b):
    if len(b) != 32:
        return None
    n = int.from_bytes(b, "little")
    y, sign = n & ((1 << 255) - 1), n >> 255
    x = _recover_x(y, sign)
    return None if x is None else _point(y, x)


def _equal(p, q):
    return (p[0] * q[2] - q[0] * p[2]) % P == 0 and (p[1] * q[2] - q[1] * p[2]) % P == 0


def _small_order(p):
    """True when [8]p is the identity: p lies in the order-1/2/4/8 subgroup."""
    q = mul(8, p)
    return q[0] % P == 0 and (q[1] - q[2]) % P == 0


def verify(public_key, message, signature):
    """True only for a valid signature of `message` under the 32-byte `public_key`."""
    if len(public_key) != 32 or len(signature) != 64:
        return False
    a, r = decode(public_key), decode(signature[:32])
    s = int.from_bytes(signature[32:], "little")
    if a is None or r is None or s >= L or _small_order(a) or _small_order(r):
        return False
    h = int.from_bytes(hashlib.sha512(signature[:32] + public_key + message).digest(), "little") % L
    return _equal(mul(s, BASE), _add(r, mul(h, a)))


def raw_key_from_spki(spki_b64):
    """The raw 32-byte key of a base64 SPKI DER Ed25519 public key, or None."""
    try:
        der = base64.b64decode(spki_b64, validate=True)
    except (ValueError, TypeError):
        return None
    if len(der) != 44 or not der.startswith(SPKI_PREFIX):
        return None
    return der[12:]


def key_id(spki_b64):
    """`kid`: the first 16 hex characters of sha256 over the SPKI DER bytes."""
    return hashlib.sha256(base64.b64decode(spki_b64)).hexdigest()[:16]
