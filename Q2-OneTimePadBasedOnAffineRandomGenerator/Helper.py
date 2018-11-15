import string

digs = string.digits + string.ascii_letters


def int2base(x, base):
    if not isinstance(x, int):
        x = int(x, 10)
    if x < 0:
        sign = -1
    elif x == 0:
        return digs[0]
    else:
        sign = 1

    x *= sign
    digits = []

    while x:
        digits.append(digs[int(x % base)])
        x = x // base

    if sign < 0:
        digits.append('-')

    digits.reverse()
    return ''.join(digits)


def binaryStr(str):
    return bin(str)[2:]


def l(str):
    print("[✨] %s " % str)


def bitcount(n):
    a = 1
    while 1 << a <= n:
        a <<= 1


def calculate_max_bits_for_number(num):
    bits = 1
    max_size = 1
    while num > max_size:
        bits += 1
        max_size = (max_size << 1) | max_size
    return bits


def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return g, x - (b // a) * y, y


def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        #return False
        raise Exception('modular inverse does not exist')
    else:
        return x % m
