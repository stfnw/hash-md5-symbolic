#!/usr/bin/python3

# Symbolic version based on https://datatracker.ietf.org/doc/html/rfc1321.
# Derived from the RSA Data Security, Inc. MD5 Message-Digest Algorithm.


import z3
from typing import Callable
import sys

MD5_HASH_BITLEN = 128


def main() -> None:
    # This is only needed when hashing large strings.
    sys.set_int_max_str_digits(0)
    z3.set_param(verbose=2)

    # Sanity check that the symbolic implementation is correct by passing
    # fully determined input.
    # assert "b10a8db164e0754105b7a99be72e3fe5" == md5hash_(b"Hello World")
    # assert "b223cca8b360eae4e49568512e2de29f" == md5hash_(b"1" * 10000)
    # => that works

    data = z3.BitVec("data", MD5_HASH_BITLEN + 8)
    print(
        f"[+] Constructing bitvector of {data.size()} bits "
        + "and the symbolic hash computation for it"
    )
    hash = md5hash(data)

    print("[+] Adding additional constraints to the solver")

    # Find message whose checksum ends with one null byte.
    # s.add(z3.Extract(7, 0, hash) == z3.BitVecVal(0, 8))

    # Find message whose checksum starts with one null byte.
    # s.add(
    #     z3.Extract(MD5_HASH_BITLEN - 1, MD5_HASH_BITLEN - 8, hash)
    #     == z3.BitVecVal(0, 8)
    # )

    # Find message whose checksum starts and ends with four null bits.
    # s.add(z3.Extract(4 - 1, 0, hash) == z3.BitVecVal(0, 4))
    # s.add(
    #     z3.Extract(MD5_HASH_BITLEN - 1, MD5_HASH_BITLEN - 4, hash)
    #     == z3.BitVecVal(0, 4)
    # )

    # Find message whose checksum ends with two null bytes.
    # s.add(z3.Extract(2 * 8 - 1, 0, hash) == z3.BitVecVal(0, 2 * 8))

    for i in range(4):
        s = z3.Solver()

        # Iterate null-nibbles.
        s.add(z3.Extract(4 * (i + 1) - 1, 4 * i, hash) == z3.BitVecVal(0, 4))
        print("[+] Checking for boolean satisfiability")
        if s.check() == z3.sat:
            print("[+] Found valid model")

            m = s.model()
            dataval = m.evaluate(data)

            print(f"    Data hex: {hex_from_bv(dataval)}")
            print(f"    MD5 hash: {hex_from_bv(m.evaluate(hash))}")


def bv_from_bytes(input: bytes, size: int | None = None) -> z3.BitVecRef:
    n = int.from_bytes(input, byteorder="big")
    if size is None:
        size = len(input) * 8
    return z3.BitVecVal(n, size)


def bytes_from_bv(input: z3.BitVecRef) -> bytes:
    bitstring = z3.simplify(input).as_binary_string()
    length = (input.size() + 7) // 8
    return int(bitstring, 2).to_bytes(length, "big")


def hex_from_bv(input: z3.BitVecRef) -> str:
    bs = bytes_from_bv(input)
    return bytes.hex(bs)


S11 = z3.BitVecVal(7, 32)
S12 = z3.BitVecVal(12, 32)
S13 = z3.BitVecVal(17, 32)
S14 = z3.BitVecVal(22, 32)
S21 = z3.BitVecVal(5, 32)
S22 = z3.BitVecVal(9, 32)
S23 = z3.BitVecVal(14, 32)
S24 = z3.BitVecVal(20, 32)
S31 = z3.BitVecVal(4, 32)
S32 = z3.BitVecVal(11, 32)
S33 = z3.BitVecVal(16, 32)
S34 = z3.BitVecVal(23, 32)
S41 = z3.BitVecVal(6, 32)
S42 = z3.BitVecVal(10, 32)
S43 = z3.BitVecVal(15, 32)
S44 = z3.BitVecVal(21, 32)


def F(x: z3.BitVecRef, y: z3.BitVecRef, z: z3.BitVecRef) -> z3.BitVecRef:
    assert x.size() == 32
    assert y.size() == 32
    assert z.size() == 32
    return (x & y) | ((~x) & z)


def G(x: z3.BitVecRef, y: z3.BitVecRef, z: z3.BitVecRef) -> z3.BitVecRef:
    assert x.size() == 32
    assert y.size() == 32
    assert z.size() == 32
    return (x & z) | (y & (~z))


def H(x: z3.BitVecRef, y: z3.BitVecRef, z: z3.BitVecRef) -> z3.BitVecRef:
    assert x.size() == 32
    assert y.size() == 32
    assert z.size() == 32
    return x ^ y ^ z


def I(x: z3.BitVecRef, y: z3.BitVecRef, z: z3.BitVecRef) -> z3.BitVecRef:
    assert x.size() == 32
    assert y.size() == 32
    assert z.size() == 32
    return y ^ (x | (~z))


def XX(
    f: Callable[[z3.BitVecRef, z3.BitVecRef, z3.BitVecRef], z3.BitVecRef],
    a: z3.BitVecRef,
    b: z3.BitVecRef,
    c: z3.BitVecRef,
    d: z3.BitVecRef,
    x: z3.BitVecRef,
    s: z3.BitVecRef,
    ac: int,
) -> z3.BitVecRef:
    return z3.simplify(bv_rotate_left(a + f(b, c, d) + x + z3.BitVecVal(ac, 32), s) + b)


def FF(a, b, c, d, x, s, ac) -> z3.BitVecRef:  # type: ignore
    return XX(F, a, b, c, d, x, s, ac)


def GG(a, b, c, d, x, s, ac) -> z3.BitVecRef:  # type: ignore
    return XX(G, a, b, c, d, x, s, ac)


def HH(a, b, c, d, x, s, ac) -> z3.BitVecRef:  # type: ignore
    return XX(H, a, b, c, d, x, s, ac)


def II(a, b, c, d, x, s, ac) -> z3.BitVecRef:  # type: ignore
    return XX(I, a, b, c, d, x, s, ac)


def md5hash(data: z3.BitVecRef) -> z3.BitVecRef:
    m = MD5()
    m.update(data)
    return z3.simplify(m.final())


def md5hash_(val: bytes) -> str:
    m = MD5()
    m.update(bv_from_bytes(val))
    digest = m.final()
    return hex_from_bv(digest)


class U8:
    def __init__(self, val: int):
        self.maxval = 0xFF
        self.val = self.maxval & val

    def __str__(self) -> str:
        return str(self.val)


# Note that padding depends only on the input length, which is known beforehand
# on each run => we don't need to use z3's symbolic BitVec type for this.
PADDING = b"\x80" + b"\x00" * 63


class MD5:

    def __init__(self) -> None:
        self.state = [
            z3.BitVecVal(0x67452301, 32),
            z3.BitVecVal(0xEFCDAB89, 32),
            z3.BitVecVal(0x98BADCFE, 32),
            z3.BitVecVal(0x10325476, 32),
        ]
        self.count = 0
        self.buffer = z3.BitVecVal(0, 64 * 8)

    def update(self, input: z3.BitVecRef) -> None:
        assert input.size() % 8 == 0
        index = self.count & 0x1FF

        self.count += input.size()

        partLen = 512 - index

        assert self.count % 8 == 0
        assert index % 8 == 0
        assert partLen % 8 == 0

        if input.size() >= partLen:
            self.buffer = bv_memcpy(
                self.buffer,
                z3.Extract(partLen - 1, 0, input),
                index,
                partLen,
            )
            self.state = transform(self.state, self.buffer)

            i = partLen
            while i + 512 - 1 < input.size():
                self.state = transform(self.state, z3.Extract(i + 512 - 1, i, input))
                i += 512

            index = 0

        else:
            i = 0

        if input.size() - i != 0:
            self.buffer = bv_memcpy(
                self.buffer,
                z3.Extract(input.size() - 1, i, input),
                index,
                input.size() - i,
            )

    def final(self) -> z3.BitVecRef:
        bits = encode(
            [z3.BitVecVal(self.count, 32), z3.BitVecVal(self.count >> 32, 32)]
        )

        index = (self.count >> 3) & 0x3F
        padLen = (56 if index < 56 else 120) - index

        self.update(bv_from_bytes(PADDING[:padLen]))
        self.update(bits)

        digest = encode(self.state)
        return digest


# def encode(input: list[U32]) -> list[U8]:
def encode(input: list[z3.BitVecRef]) -> z3.BitVecRef:
    for e in input:
        assert e.size() % 32 == 0

    outlen = len(input) * 32
    res = z3.BitVecVal(0, outlen)

    i = 0
    for j in range(0, outlen, 32):
        res = bv_memcpy(res, z3.Extract(1 * 8 - 1, 0 * 8, input[i]), j + 0 * 8, 8)
        res = bv_memcpy(res, z3.Extract(2 * 8 - 1, 1 * 8, input[i]), j + 1 * 8, 8)
        res = bv_memcpy(res, z3.Extract(3 * 8 - 1, 2 * 8, input[i]), j + 2 * 8, 8)
        res = bv_memcpy(res, z3.Extract(4 * 8 - 1, 3 * 8, input[i]), j + 3 * 8, 8)
        i += 1

    res = z3.simplify(res)

    return res


# def decode(input: list[U8]) -> list[U32]:
def decode(input: z3.BitVecRef) -> list[z3.BitVecRef]:
    assert input.size() % 32 == 0, f"Input has length {len(input)}"

    res = [z3.BitVecVal(0, 32) for _ in range(input.size() // 32)]

    i = len(res) - 1
    for j in range(0, input.size(), 32):
        res[i] |= z3.ZeroExt(24, z3.Extract(j + 1 * 8 - 1, j + 0 * 8, input)) << (3 * 8)
        res[i] |= z3.ZeroExt(24, z3.Extract(j + 2 * 8 - 1, j + 1 * 8, input)) << (2 * 8)
        res[i] |= z3.ZeroExt(24, z3.Extract(j + 3 * 8 - 1, j + 2 * 8, input)) << (1 * 8)
        res[i] |= z3.ZeroExt(24, z3.Extract(j + 4 * 8 - 1, j + 3 * 8, input)) << (0 * 8)
        i -= 1

    res = [z3.simplify(el) for el in res]

    return res


def transform(state: list[z3.BitVecRef], block: z3.BitVecRef) -> list[z3.BitVecRef]:
    assert len(state) == 4, f"State has length f{len(block)}"
    assert (
        state[0].size() == 32
        and state[1].size() == 32
        and state[2].size() == 32
        and state[3].size() == 32
    )
    assert block.size() == 64 * 8, f"Block has length f{block.size()}"

    a, b, c, d = state

    x = decode(block)

    # Round 1
    a = FF(a, b, c, d, x[0], S11, 0xD76AA478)  #   1
    d = FF(d, a, b, c, x[1], S12, 0xE8C7B756)  #   2
    c = FF(c, d, a, b, x[2], S13, 0x242070DB)  #   3
    b = FF(b, c, d, a, x[3], S14, 0xC1BDCEEE)  #   4
    a = FF(a, b, c, d, x[4], S11, 0xF57C0FAF)  #   5
    d = FF(d, a, b, c, x[5], S12, 0x4787C62A)  #   6
    c = FF(c, d, a, b, x[6], S13, 0xA8304613)  #   7
    b = FF(b, c, d, a, x[7], S14, 0xFD469501)  #   8
    a = FF(a, b, c, d, x[8], S11, 0x698098D8)  #   9
    d = FF(d, a, b, c, x[9], S12, 0x8B44F7AF)  #  10
    c = FF(c, d, a, b, x[10], S13, 0xFFFF5BB1)  # 11
    b = FF(b, c, d, a, x[11], S14, 0x895CD7BE)  # 12
    a = FF(a, b, c, d, x[12], S11, 0x6B901122)  # 13
    d = FF(d, a, b, c, x[13], S12, 0xFD987193)  # 14
    c = FF(c, d, a, b, x[14], S13, 0xA679438E)  # 15
    b = FF(b, c, d, a, x[15], S14, 0x49B40821)  # 16

    # Round 2
    a = GG(a, b, c, d, x[1], S21, 0xF61E2562)  #  17
    d = GG(d, a, b, c, x[6], S22, 0xC040B340)  #  18
    c = GG(c, d, a, b, x[11], S23, 0x265E5A51)  # 19
    b = GG(b, c, d, a, x[0], S24, 0xE9B6C7AA)  #  20
    a = GG(a, b, c, d, x[5], S21, 0xD62F105D)  #  21
    d = GG(d, a, b, c, x[10], S22, 0x2441453)  #  22
    c = GG(c, d, a, b, x[15], S23, 0xD8A1E681)  # 23
    b = GG(b, c, d, a, x[4], S24, 0xE7D3FBC8)  #  24
    a = GG(a, b, c, d, x[9], S21, 0x21E1CDE6)  #  25
    d = GG(d, a, b, c, x[14], S22, 0xC33707D6)  # 26
    c = GG(c, d, a, b, x[3], S23, 0xF4D50D87)  #  27
    b = GG(b, c, d, a, x[8], S24, 0x455A14ED)  #  28
    a = GG(a, b, c, d, x[13], S21, 0xA9E3E905)  # 29
    d = GG(d, a, b, c, x[2], S22, 0xFCEFA3F8)  #  30
    c = GG(c, d, a, b, x[7], S23, 0x676F02D9)  #  31
    b = GG(b, c, d, a, x[12], S24, 0x8D2A4C8A)  # 32

    # Round 3
    a = HH(a, b, c, d, x[5], S31, 0xFFFA3942)  #  33
    d = HH(d, a, b, c, x[8], S32, 0x8771F681)  #  34
    c = HH(c, d, a, b, x[11], S33, 0x6D9D6122)  # 35
    b = HH(b, c, d, a, x[14], S34, 0xFDE5380C)  # 36
    a = HH(a, b, c, d, x[1], S31, 0xA4BEEA44)  #  37
    d = HH(d, a, b, c, x[4], S32, 0x4BDECFA9)  #  38
    c = HH(c, d, a, b, x[7], S33, 0xF6BB4B60)  #  39
    b = HH(b, c, d, a, x[10], S34, 0xBEBFBC70)  # 40
    a = HH(a, b, c, d, x[13], S31, 0x289B7EC6)  # 41
    d = HH(d, a, b, c, x[0], S32, 0xEAA127FA)  #  42
    c = HH(c, d, a, b, x[3], S33, 0xD4EF3085)  #  43
    b = HH(b, c, d, a, x[6], S34, 0x4881D05)  #   44
    a = HH(a, b, c, d, x[9], S31, 0xD9D4D039)  #  45
    d = HH(d, a, b, c, x[12], S32, 0xE6DB99E5)  # 46
    c = HH(c, d, a, b, x[15], S33, 0x1FA27CF8)  # 47
    b = HH(b, c, d, a, x[2], S34, 0xC4AC5665)  #  48

    # Round 4
    a = II(a, b, c, d, x[0], S41, 0xF4292244)  #  49
    d = II(d, a, b, c, x[7], S42, 0x432AFF97)  #  50
    c = II(c, d, a, b, x[14], S43, 0xAB9423A7)  # 51
    b = II(b, c, d, a, x[5], S44, 0xFC93A039)  #  52
    a = II(a, b, c, d, x[12], S41, 0x655B59C3)  # 53
    d = II(d, a, b, c, x[3], S42, 0x8F0CCC92)  #  54
    c = II(c, d, a, b, x[10], S43, 0xFFEFF47D)  # 55
    b = II(b, c, d, a, x[1], S44, 0x85845DD1)  #  56
    a = II(a, b, c, d, x[8], S41, 0x6FA87E4F)  #  57
    d = II(d, a, b, c, x[15], S42, 0xFE2CE6E0)  # 58
    c = II(c, d, a, b, x[6], S43, 0xA3014314)  #  59
    b = II(b, c, d, a, x[13], S44, 0x4E0811A1)  # 60
    a = II(a, b, c, d, x[4], S41, 0xF7537E82)  #  61
    d = II(d, a, b, c, x[11], S42, 0xBD3AF235)  # 62
    c = II(c, d, a, b, x[2], S43, 0x2AD7D2BB)  #  63
    b = II(b, c, d, a, x[9], S44, 0xEB86D391)  #  64

    return [state[0] + a, state[1] + b, state[2] + c, state[3] + d]


# Replace part of a bit vector with another bit vector.
# Treats bitvectors as big endian bit arrays
def bv_memcpy(
    dst: z3.BitVecRef, src: z3.BitVecRef, ifrom: int, length: int
) -> z3.BitVecRef:
    assert length > 0
    assert src.size() == length
    assert ifrom + length <= dst.size()  # both are exclusive of the last position

    # endianness
    ifrom, ito = dst.size() - (ifrom + length), dst.size() - ifrom

    # mask in big-endian bit representation
    #    ifrom     ito
    #        |     |
    # ...111 0...0 111...
    mask = 0
    mask |= (1 << ifrom) - 1  #  LSBs
    mask |= ~((1 << ito) - 1)  # MSBs

    new = z3.ZeroExt(dst.size() - src.size(), src)
    new = new << ifrom

    dst = dst & mask  # clear range
    dst = dst | new  #  assign new value

    return z3.simplify(dst)


def bv_rotate_left(x: z3.BitVecRef, n: z3.BitVecRef) -> z3.BitVecRef:
    return (x << n) | z3.LShR(x, (x.size() - n))


if __name__ == "__main__":
    main()
