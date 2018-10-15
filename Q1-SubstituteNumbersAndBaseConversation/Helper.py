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
    print("[*] %s " % str)


def bitcount(n):
    a = 1
    while 1 << a <= n:
        a <<= 1
