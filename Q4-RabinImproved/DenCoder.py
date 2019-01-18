import os
from copy import deepcopy

from Helper import l, calculate_max_bits_for_number, modinv, egcd, powmod, is_prime
from math import ceil, floor
import configparser
from progress.bar import ChargingBar
from functools import reduce


class DenCoder:
    def __init__(self, p, q):
        assert (p % 4 == 3 and is_prime(p))
        assert (q % 4 == 3 and is_prime(q))
        self.p = p
        self.q = q
        self.pq = p * q
        self.mode = (p ** 2) * q

        self.chunk_size_pt = (self.pq.bit_length() - 1) // 8
        self.chunk_size_ct = ceil(self.mode.bit_length() / 8)

    @staticmethod
    def save_key(file_object, p, q):
        config = configparser.ConfigParser()
        config['key'] = {
            'p': p,
            'q': q
        }
        config.write(file_object)

    @staticmethod
    def read_key(file_object):
        config = configparser.ConfigParser()
        config.read_file(file_object)
        p = config.getint('key', 'p')
        q = config.getint('key', 'q')
        return DenCoder(p, q)

    def encryption_chunk_reader(self, f, chunk_size):
        while True:
            data = f.read(chunk_size)
            if not data:
                break
            yield int.from_bytes(data, 'little')

    def decryption_chunk_reader(self, f, chunk_size):
        file_size = os.stat(f.name).st_size

        lastblock_size = int.from_bytes(f.read(10), 'little')
        if lastblock_size == 0:
            lastblock_size = self.chunk_size_pt
        while True:
            data = f.read(chunk_size)
            if not data:
                break
            if f.tell() < file_size:
                yield int.from_bytes(data, 'little'), self.chunk_size_pt
            else:
                yield int.from_bytes(data, 'little'), lastblock_size

    def encrypt_file(self, plaintext_file_name, ciphertext_file_name):
        pt_file = open(plaintext_file_name, "rb")
        ct_file = open(ciphertext_file_name, 'wb+')

        file_size = os.stat(plaintext_file_name).st_size
        bar = ChargingBar('[*] Encrypting ', max=(file_size // self.chunk_size_pt) - 1)
        last_block_size = file_size % (self.chunk_size_pt)

        ct_file.write(last_block_size.to_bytes(10, byteorder='little'))

        for chunk in self.encryption_chunk_reader(pt_file, self.chunk_size_pt):
            cipher = powmod(chunk, 2, self.mode)
            ct_file.write(cipher.to_bytes(self.chunk_size_ct, byteorder='little'))
            bar.next()
        bar.finish()
        l("Encryption done")
        l("Saved at %s" % os.path.abspath(ct_file.name))

    def is_valid_m(self, c, m, n):
        w = (c - (m ** 2)) / n

        return w % 1 == 0

    def decrypt_file(self, ciphertext_file_name, plaintext_file_name):
        ct_file = open(ciphertext_file_name, "rb")
        pt_file = open(plaintext_file_name, 'wb+')
        file_size = os.stat(ciphertext_file_name).st_size

        bar = ChargingBar('[*] Decrypting ', max=(file_size // self.chunk_size_ct) - 1)

        p, q = self.p, self.q
        pq = self.pq
        n = self.mode

        for i, (chunk, chunk_size) in enumerate(self.decryption_chunk_reader(ct_file, self.chunk_size_ct)):

            m_p = powmod(chunk, ((p + 1) // 4), p)
            m_q = powmod(chunk, ((q + 1) // 4), q)
            _, r, s = egcd(p, q)

            assert (r * p + s * q == 1)

            rpm_q = r * p * m_q
            sqm_p = s * q * m_p

            m1 = (rpm_q + sqm_p) % pq
            bar.next()
            if self.is_valid_m(chunk, m1, n):
                pt_file.write(m1.to_bytes(chunk_size, byteorder='little'))
                continue

            m2 = (rpm_q - sqm_p) % pq
            if self.is_valid_m(chunk, m2, n):
                pt_file.write(m2.to_bytes(chunk_size, byteorder='little'))
                continue

            m3 = -m2 % pq
            if self.is_valid_m(chunk, m3, n):
                pt_file.write(m3.to_bytes(chunk_size, byteorder='little'))
                continue

            m4 = -m1 % pq
            if self.is_valid_m(chunk, m4, n):
                pt_file.write(m4.to_bytes(chunk_size, byteorder='little'))
                continue
            assert False
        bar.finish()
        l("Decryption done")
        l("Saved at %s" % os.path.abspath(pt_file.name))
