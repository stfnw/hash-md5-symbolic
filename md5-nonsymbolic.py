#!/usr/bin/python3

# Non-symbolic version based on
# https://datatracker.ietf.org/doc/html/rfc1321. Derived from the RSA Data
# Security, Inc. MD5 Message-Digest Algorithm. Self-contained single-file
# implementation; with macros replaced with functions.


class U32:
    def __init__(self, val: int):
        self.maxval = 0xFFFFFFFF
        self.val = self.maxval & val

    def __str__(self) -> str:
        return str(self.val)

    def __add__(a: "U32", b: "U32") -> "U32":
        return U32(a.val + b.val)

    def __and__(a: "U32", b: "U32") -> "U32":
        return U32(a.val & b.val)

    def __or__(a: "U32", b: "U32") -> "U32":
        return U32(a.val | b.val)

    def __invert__(a: "U32") -> "U32":
        return U32(~a.val)

    def __xor__(a: "U32", b: "U32") -> "U32":
        return U32(a.val ^ b.val)

    def __lshift__(a: "U32", b: "U32") -> "U32":
        return U32(a.val << b.val)

    def __rshift__(a: "U32", b: "U32") -> "U32":
        return U32(a.val >> b.val)

    def rotate_left(x: "U32", n: "U32") -> "U32":
        return (x << n) | (x >> U32(32 - n.val))

    @staticmethod
    def from_u8(val: "U8") -> "U32":
        return U32(val.val)


class U8:
    def __init__(self, val: int):
        self.maxval = 0xFF
        self.val = self.maxval & val

    def __str__(self) -> str:
        return str(self.val)

    def __add__(a: "U8", b: "U8") -> "U8":
        return U8(a.val + b.val)

    def __and__(a: "U8", b: "U8") -> "U8":
        return U8(a.val & b.val)

    def __or__(a: "U8", b: "U8") -> "U8":
        return U8(a.val | b.val)

    def __invert__(a: "U8") -> "U8":
        return U8(~a.val)

    def __xor__(a: "U8", b: "U8") -> "U8":
        return U8(a.val ^ b.val)

    def __lshift__(a: "U8", b: "U8") -> "U8":
        return U8(a.val << b.val)

    def __rshift__(a: "U8", b: "U8") -> "U8":
        return U8(a.val >> b.val)

    def rotate_left(x: "U8", n: "U8") -> "U8":
        return (x << n) | (x >> U8(32 - n.val))


def frombytes(input: bytes) -> list[U8]:
    return [U8(b) for b in input]


def tobytes(input: list[U8]) -> bytes:
    return bytes([b.val for b in input])


S11: U32 = U32(7)
S12: U32 = U32(12)
S13: U32 = U32(17)
S14: U32 = U32(22)
S21: U32 = U32(5)
S22: U32 = U32(9)
S23: U32 = U32(14)
S24: U32 = U32(20)
S31: U32 = U32(4)
S32: U32 = U32(11)
S33: U32 = U32(16)
S34: U32 = U32(23)
S41: U32 = U32(6)
S42: U32 = U32(10)
S43: U32 = U32(15)
S44: U32 = U32(21)


def F(x: U32, y: U32, z: U32) -> U32:
    return (x & y) | ((~x) & z)


def G(x: U32, y: U32, z: U32) -> U32:
    return (x & z) | (y & (~z))


def H(x: U32, y: U32, z: U32) -> U32:
    return x ^ y ^ z


def I(x: U32, y: U32, z: U32) -> U32:
    return y ^ (x | (~z))


def FF(a: U32, b: U32, c: U32, d: U32, x: U32, s: U32, ac: int) -> U32:
    tmp1 = a + F(b, c, d) + x + U32(ac)
    tmp2 = tmp1.rotate_left(s)
    tmp3 = tmp2 + b
    return tmp3


def GG(a: U32, b: U32, c: U32, d: U32, x: U32, s: U32, ac: int) -> U32:
    tmp1 = a + G(b, c, d) + x + U32(ac)
    tmp2 = tmp1.rotate_left(s)
    tmp3 = tmp2 + b
    return tmp3


def HH(a: U32, b: U32, c: U32, d: U32, x: U32, s: U32, ac: int) -> U32:
    tmp1 = a + H(b, c, d) + x + U32(ac)
    tmp2 = tmp1.rotate_left(s)
    tmp3 = tmp2 + b
    return tmp3


def II(a: U32, b: U32, c: U32, d: U32, x: U32, s: U32, ac: int) -> U32:
    tmp1 = a + I(b, c, d) + x + U32(ac)
    tmp2 = tmp1.rotate_left(s)
    tmp3 = tmp2 + b
    return tmp3


PADDING = [U8(0)] * 64
PADDING[0] = U8(0x80)


def md5hash(val: bytes) -> str:
    m = MD5()
    m.update(frombytes(val))
    digest = m.final()
    return bytes.hex(tobytes(digest))


class MD5:

    def __init__(self) -> None:
        self.state = [
            U32(0x67452301),
            U32(0xEFCDAB89),
            U32(0x98BADCFE),
            U32(0x10325476),
        ]
        self.count = [U32(0), U32(0)]
        self.buffer = [U8(0)] * 64

    def update(self, input: list[U8]) -> None:
        index = (self.count[0].val >> 3) & 0x3F

        self.count[0] += U32(len(input) << 3)
        if self.count[0].val < (len(input) << 3):
            self.count[1] += U32(1)
        self.count[1] += U32(len(input) >> 29)

        partLen = 64 - index

        if len(input) >= partLen:
            self.buffer[index : index + partLen] = input[:partLen]
            self.transform(self.buffer)

            i = partLen
            while i + 63 < len(input):
                self.transform(input[i : i + 64])
                i += 64

            index = 0

        else:
            i = 0

        self.buffer[index : index + len(input) - i] = input[i : len(input)]

    def transform(self, block: list[U8]) -> None:
        assert len(block) == 64, f"Block has length f{len(block)}"

        a, b, c, d = self.state

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

        self.state[0] += a
        self.state[1] += b
        self.state[2] += c
        self.state[3] += d

    def final(self) -> list[U8]:
        bits = encode(self.count)

        index = (self.count[0].val >> 3) & 0x3F
        padLen = (56 if index < 56 else 120) - index

        self.update(PADDING[:padLen])
        self.update(bits)

        digest = encode(self.state)
        return digest


def encode(input: list[U32]) -> list[U8]:
    outlen = len(input) * 4
    res = [U8(0)] * outlen

    i = 0
    for j in range(0, outlen, 4):
        res[j + 0] = U8((input[i] >> U32(0 * 8)).val)
        res[j + 1] = U8((input[i] >> U32(1 * 8)).val)
        res[j + 2] = U8((input[i] >> U32(2 * 8)).val)
        res[j + 3] = U8((input[i] >> U32(3 * 8)).val)
        i += 1

    return res


def decode(input: list[U8]) -> list[U32]:
    assert len(input) % 4 == 0, f"Input has length {len(input)}"

    res = [U32(0)] * (len(input) // 4)

    i = 0
    for j in range(0, len(input), 4):
        res[i] = (
            (U32.from_u8(input[j + 0]) << U32(0 * 8)) & U32(0xFFFFFFFF)
            | (U32.from_u8(input[j + 1]) << U32(1 * 8)) & U32(0xFFFFFFFF)
            | (U32.from_u8(input[j + 2]) << U32(2 * 8)) & U32(0xFFFFFFFF)
            | (U32.from_u8(input[j + 3]) << U32(3 * 8)) & U32(0xFFFFFFFF)
        )
        i += 1

    return res


def main() -> None:
    assert "b10a8db164e0754105b7a99be72e3fe5" == md5hash(b"Hello World")
    assert "b223cca8b360eae4e49568512e2de29f" == md5hash(b"1" * 10000)


if __name__ == "__main__":
    main()
