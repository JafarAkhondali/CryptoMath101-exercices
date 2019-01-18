def l(str):
    print("[✨] %s " % str)


def calculate_max_bits_for_number(num):
    bits = 1
    max_size = 1
    while num > max_size:
        bits += 1
        max_size = (max_size << 1) | max_size
    return bits


def powmod(a, b, c):
    if b < 3:
        return a ** b % c
    if b % 2 == 0:
        return (powmod(a, b // 2, c) ** 2) % c
    return ((powmod(a , b // 2, c) ** 2) * a) % c


def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return g, x - (b // a) * y, y


def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        # return False
        raise Exception('modular inverse does not exist')
    else:
        return x % m

def is_prime(n):
    if n == 2 or n == 3: return True
    if n < 2 or n % 2 == 0: return False
    if n < 9: return True
    if n % 3 == 0: return False
    r = int(n ** 0.5)
    f = 5
    while f <= r:
        if n % f == 0: return False
        if n % (f + 2) == 0: return False
        f += 6
    return True
