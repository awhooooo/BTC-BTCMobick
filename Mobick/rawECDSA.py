#!/usr/bin/env python3

import collections
import hashlib
import random

EllipticCurve = collections.namedtuple('EllipticCurve', 'name p a b g n h')


curve = EllipticCurve(
    'secp256k1',
    # Field characteristic.
    p=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f,
    # Curve coefficients.
    a=0,
    b=7,
    # Base point.
    g=(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
       0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8),
    # Subgroup order.
    n=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141,
    # Subgroup cofactor.
    h=1,
)


# Modular arithmetic ##########################################################

def inverse_mod(k, p):
    """Returns the inverse of k modulo p.

    This function returns the only integer x such that (x * k) % p == 1.

    k must be non-zero and p must be a prime.
    """
    if k == 0:
        raise ZeroDivisionError('division by zero')

    if k < 0:
        # k ** -1 = p - (-k) ** -1  (mod p)
        return p - inverse_mod(-k, p)

    # Extended Euclidean algorithm.
    s, old_s = 0, 1
    t, old_t = 1, 0
    r, old_r = p, k

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t

    gcd, x, y = old_r, old_s, old_t

    assert gcd == 1
    assert (k * x) % p == 1

    return x % p


# Functions that work on curve points #########################################

def is_on_curve(point):
    """Returns True if the given point lies on the elliptic curve."""
    if point is None:
        # None represents the point at infinity.
        return True

    x, y = point

    return (y * y - x * x * x - curve.a * x - curve.b) % curve.p == 0


def point_neg(point):
    """Returns -point."""
    assert is_on_curve(point)

    if point is None:
        # -0 = 0
        return None

    x, y = point
    result = (x, -y % curve.p)

    assert is_on_curve(result)

    return result


def point_add(point1, point2):
    """Returns the result of point1 + point2 according to the group law."""
    assert is_on_curve(point1)
    assert is_on_curve(point2)

    if point1 is None:
        # 0 + point2 = point2
        return point2
    if point2 is None:
        # point1 + 0 = point1
        return point1

    x1, y1 = point1
    x2, y2 = point2

    if x1 == x2 and y1 != y2:
        # point1 + (-point1) = 0
        return None

    if x1 == x2:
        # This is the case point1 == point2.
        m = (3 * x1 * x1 + curve.a) * inverse_mod(2 * y1, curve.p)
    else:
        # This is the case point1 != point2.
        m = (y1 - y2) * inverse_mod(x1 - x2, curve.p)

    x3 = m * m - x1 - x2
    y3 = y1 + m * (x3 - x1)
    result = (x3 % curve.p,
              -y3 % curve.p)

    assert is_on_curve(result)

    return result


def scalar_mult(k, point):
    """Returns k * point computed using the double and point_add algorithm."""
    assert is_on_curve(point)

    if k % curve.n == 0 or point is None:
        return None

    if k < 0:
        # k * point = -k * (-point)
        return scalar_mult(-k, point_neg(point))

    result = None
    addend = point

    while k:
        if k & 1:
            # Add.
            result = point_add(result, addend)

        # Double.
        addend = point_add(addend, addend)

        k >>= 1

    assert is_on_curve(result)

    return result


# Keypair generation and ECDSA ################################################

def make_keypair():
    """Generates a random private-public key pair."""
    private_key = random.randrange(1, curve.n)
    public_key = scalar_mult(private_key, curve.g)

    return private_key, public_key

def hash_message(message, truncate: bool):
    """Returns the truncated double SHA256 hash of the message."""
    message_hash = hashlib.sha256(hashlib.sha256(bytes.fromhex(message)).digest()).digest()
    number = int.from_bytes(message_hash, 'big')

    if truncate:
        # Truncate the integer to match the curve order length (if needed)
        max_length = curve.n.bit_length()  # Assuming we're working with a 256-bit curve
        length = len(message_hash) * 8
        number >>= max(0, length - max_length)
    else:
        pass

    return number

def sign_message(private_key, message, truncate=False):

    z = hash_message(message, truncate)
    r = 0
    s = 0

    while not r or not s:
        k = random.randrange(1, curve.n)  # <======================================
        x, y = scalar_mult(k, curve.g)

        r = x % curve.n
        s = ((z + r * private_key) * inverse_mod(k, curve.n)) % curve.n

    return (r, s)


def verify_signature(public_key, message, signature, truncate=False):
    z = hash_message(message, truncate)

    r, s = signature

    w = inverse_mod(s, curve.n)
    u1 = (z * w) % curve.n
    u2 = (r * w) % curve.n

    x, y = point_add(scalar_mult(u1, curve.g),
                     scalar_mult(u2, public_key))

    if (r % curve.n) == (x % curve.n):
        return 'signature matches'
    else:
        return 'invalid signature'


def der(r, s):

    # Ensure the "s" value is within the valid range
    if s > (curve.n / 2):
        s = curve.n - s

    # Convert the r and s parts to bytes
    rbin = r.to_bytes(32, byteorder='big')
    sbin = s.to_bytes(32, byteorder='big')

    # If r or s bins have a high bit, add a 00
    if rbin[0] >= 128:
        rbin = b'\x00' + rbin
    if sbin[0] >= 128:
        sbin = b'\x00' + sbin

    # Start building the result with the 'r' part
    result = bytes([2, len(rbin)]) + rbin

    # Append the 's' part to the result
    result += bytes([2, len(sbin)]) + sbin

    # Add the DER signature prefix and its total length
    return bytes([0x30, len(result)]) + result


def der_to_rs(der_signature):
    # Skip the initial bytes (0x30 and length)
    der_bytes = der_signature[2:]

    # Extract the 'r' component
    r_len = der_bytes[1]
    r = int.from_bytes(der_bytes[2 : 2 + r_len], byteorder='big')

    # Extract the 's' component
    s_len = der_bytes[2 + r_len + 1]
    s = int.from_bytes(der_bytes[2 + r_len + 2 :], byteorder='big')

    # keep in mind that the s value above might not be the one you are looking for
    # if not, then try the subtraction of s from the subgroup order of the curve
    # which is curve.n - s in this case
    return r, s


if __name__ == "__main__":

    print('Curve:', curve.name)

    private, public = make_keypair()
    print("Private key:", hex(private))
    print("Public key: (0x{:x}, 0x{:x})".format(*public))

    msg = b'As a result, strategy became the provenance of conservatives and neo-conservatives'
    signature = sign_message(private, msg.hex())

    print()
    print('Message:', msg)
    print('Signature: (0x{:x}, 0x{:x})'.format(*signature))
    print('Verification:', verify_signature(public, msg.hex(), signature))

    msg = b'Hi there!'
    print()
    print('Message:', msg)
    print('Verification:', verify_signature(public, msg.hex(), signature))

    private, public = make_keypair()

    msg = b'Hello!'
    print()
    print('Message:', msg)
    print("Public key: (0x{:x}, 0x{:x})".format(*public))
    print('Verification:', verify_signature(public, msg.hex(), signature))
