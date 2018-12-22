import os
import re

import numpy as np
from copy import deepcopy
import random
from Helper import l, calculate_max_bits_for_number, modinv, egcd, solve_crt
from math import ceil, floor
import configparser
from progress.bar import ChargingBar
from functools import reduce

PRIME_SIZE = 4


class DenCoder:
    def __init__(self, alpha, beta, primes):
        self.alpha = alpha
        self.beta = beta
        self.primes = primes
        self.mode = reduce((lambda x, y: x * y), primes)
        self.chunk_size = (self.mode.bit_length() // 8)

        # Calculate block padding
        self.max_block_size_after_encrypt_bits = self.chunk_size * 8
        self.max_block_size_after_encrypt_bytes = self.chunk_size
        self.padding_block_size_bytes = self.calculate_padding_length(self.max_block_size_after_encrypt_bits)

    @staticmethod
    def calculate_padding_length(max_block_size_after_encrypt_bits):
        bytes = 1
        base = 255
        while True:
            if max_block_size_after_encrypt_bits <= base:
                break
            bytes += 1
            base = (base << 8) | 255
        return bytes

    @staticmethod
    def save_key(file_object, alpha, beta, primes):
        config = configparser.ConfigParser()
        config['key'] = {
            'alpha': alpha,
            'beta': beta,
            'primes': str(primes)[1:-1]
        }
        config.write(file_object)

    @staticmethod
    def read_key(file_object):
        config = configparser.ConfigParser()
        config.read_file(file_object)
        alpha = config.getint('key', 'alpha')
        beta = config.getint('key', 'beta')
        primes = [int(p) for p in config.get('key', 'primes').split(',')]
        return DenCoder(alpha=alpha, beta=beta, primes=primes)

    def encryption_chunk_reader(self, f, chunk_size):
        while True:
            data = f.read(chunk_size)
            if not data:
                break
            yield int.from_bytes(data, 'little')

    def decryption_chunk_reader(self, f, prime_size, chunk_size):
        file_size = os.stat(f.name).st_size

        lastblock_size = int.from_bytes(f.read(10), 'little')
        #yield int.from_bytes(lastblock_size, 'little')
        while True:
            data = f.read(prime_size)
            if not data:
                break
            if f.tell() < file_size:
                yield int.from_bytes(data, 'little'), chunk_size
            else:
                yield int.from_bytes(data, 'little'), lastblock_size

    def encrypt_file(self, plaintext_file_name, ciphertext_file_name):
        pt_file = open(plaintext_file_name, "rb")
        ct_file = open(ciphertext_file_name, 'wb+')

        file_size = os.stat(plaintext_file_name).st_size
        bar = ChargingBar('[*] Encrypting ', max=(file_size // self.chunk_size) - 1)
        last_block_size = file_size % self.chunk_size

        ct_file.write(last_block_size.to_bytes(10, byteorder='little'))

        for chunk in self.encryption_chunk_reader(pt_file, self.chunk_size):
            # print('Before: %d' % chunk)
            cts=[]
            for p in self.primes:
                ZZ = (chunk % p)
                # print('PlainText: %d' % ZZ)
                XX = (self.alpha * ZZ + self.beta) % p
                # print('Cipher: %d' % XX)
                cts.append(XX)

            # cts = [XX for p in self.primes]
            # print('Aggr: %s' % cts)
            for i, ct in enumerate(cts):
                x = ct.to_bytes(PRIME_SIZE, byteorder='little')
                # print('Int: %d' % x)
                ct_file.write(x)
                # print(x)
            # print('-'*30)
            bar.next()
        bar.finish()
        l("Encryption done")
        l("Saved at %s" % os.path.abspath(ct_file.name))

    def decrypt_file(self, ciphertext_file_name, plaintext_file_name):
        ct_file = open(ciphertext_file_name, "rb")
        pt_file = open(plaintext_file_name, 'wb+')
        file_size = os.stat(plaintext_file_name).st_size
        bar = ChargingBar('[*] Decrypting ', max=(file_size // self.chunk_size) - 1)

        # Read cipher text chunk
        cts = []
        count_of_primes = len(self.primes)
        for i, (chunk, chunk_size) in enumerate(self.decryption_chunk_reader(ct_file, PRIME_SIZE, self.chunk_size)):
            chunk = ((chunk - self.beta) * modinv(self.alpha, self.primes[i % count_of_primes])) % self.primes[i % count_of_primes]
            cts.append(chunk)
            if len(cts) < count_of_primes:
                continue
            bar.next()
            ct = solve_crt(cts, self.primes)
            pt_file.write(ct.to_bytes(chunk_size, byteorder='little'))
            cts = []
        bar.finish()
        l("Decryption done")
        l("Saved at %s" % os.path.abspath(pt_file.name))

    @staticmethod
    def affinehill(alpha, beta, x, mode, val):
        c = (alpha * x + beta) % mode
        if c == val:
            return True
        raise Exception("Not possible: %s != %s" % (c, val))

    @staticmethod
    def extract_key(ciphertext_file, plaintext_file, mode_from, mode_to, key_file):
        PT_DATA = int.from_bytes(open(plaintext_file, 'rb').read(), 'big')
        CT_DATA = int.from_bytes(open(ciphertext_file, 'rb').read(), 'big')

        l("Starting key extraction")
        alpha = beta = seed = mode = 0
        found_key = False
        for mode in range(mode_from, mode_to + 1):
            chunk_size = calculate_max_bits_for_number(mode)

            P1_HILL = PT_DATA & (2 ** chunk_size - 1)
            C1 = CT_DATA & (2 ** chunk_size - 1)

            P2_HILL = (PT_DATA >> chunk_size) & (2 ** chunk_size - 1)
            C2 = (CT_DATA >> chunk_size) & (2 ** chunk_size - 1)

            P3_HILL = (PT_DATA >> (2 * chunk_size)) & (2 ** chunk_size - 1)
            C3 = (CT_DATA >> (2 * chunk_size)) & (2 ** chunk_size - 1)

            P4_HILL = (PT_DATA >> (3 * chunk_size)) & (2 ** chunk_size - 1)
            C4 = (CT_DATA >> (3 * chunk_size)) & (2 ** chunk_size - 1)

            P5_HILL = (PT_DATA >> (4 * chunk_size)) & (2 ** chunk_size - 1)
            C5 = (CT_DATA >> (4 * chunk_size)) & (2 ** chunk_size - 1)

            l("Checking mode %s" % mode)
            try:

                X1 = P1_HILL ^ C1
                X2 = P2_HILL ^ C2
                X3 = P3_HILL ^ C3
                X4 = P4_HILL ^ C4
                X5 = P5_HILL ^ C5

                gcd, __, ___ = egcd((X3 - X4) % mode, mode)

                gcd_flag = False
                if gcd != 1:
                    alpha = ((((X4 - X5) % mode) // gcd) * modinv(((X3 - X4) % mode) // gcd, mode // gcd)) % (
                            mode // gcd)
                    gcd_flag = True
                else:
                    alpha = (((X4 - X5) % mode) * modinv((X3 - X4) % mode, mode)) % mode

                if gcd_flag:
                    for alpha_test in range(alpha, mode + 1, gcd):
                        try:
                            # alpha * X1 + beta % mode = X2
                            # beta % mode = X2 - alpha * X1
                            beta = (X3 - (alpha_test * X2) % mode) % mode

                            # alpha * seed + beta % mode = X1
                            # seed = X1 - beta * (alpha ^ -1 )
                            seed = ((X1 - beta) * (modinv(alpha_test, mode))) % mode

                            DenCoder.affinehill(alpha_test, beta, seed, mode, X1)
                            DenCoder.affinehill(alpha_test, beta, X1, mode, X2)
                            DenCoder.affinehill(alpha_test, beta, X2, mode, X3)
                            DenCoder.affinehill(alpha_test, beta, X3, mode, X4)
                            # DenCoder.affinehill(alpha, beta, X4, mode, X5)

                            l("-" * 40)
                            l("%s is a valid mode :)" % mode)

                            l("alpha: %s" % alpha_test)
                            l("beta: %s" % beta)
                            l("seed: %s" % seed)
                            l("mode: %s" % mode)

                            DenCoder.save_key(key_file, alpha_test, beta, seed, mode)
                            l("You key has been saved in " + os.path.abspath(key_file.name))
                            found_key = True
                            # break
                        except Exception as e:
                            continue
                else:
                    beta = (X2 - alpha * X1) % mode

                    # alpha * seed + beta % mode = X1
                    # seed = X1 - beta * (alpha ^ -1 )
                    seed = ((X1 - beta) * (modinv(alpha, mode))) % mode

                    DenCoder.affinehill(alpha, beta, seed, mode, X1)
                    DenCoder.affinehill(alpha, beta, X1, mode, X2)
                    DenCoder.affinehill(alpha, beta, X2, mode, X3)
                    DenCoder.affinehill(alpha, beta, X3, mode, X4)
                    # DenCoder.affinehill(alpha, beta, X4, mode, X5)

                    l("-" * 40)
                    l("%s is a valid mode :)" % mode)

                    l("alpha: %s" % alpha)
                    l("beta: %s" % beta)
                    l("seed: %s" % seed)
                    l("mode: %s" % mode)

                    DenCoder.save_key(key_file, alpha, beta, seed, mode)
                    l("You key has been saved in " + os.path.abspath(key_file.name))
                    found_key = True
            except Exception as e:
                pass

        if not found_key:
            l("Sorry i wasn't able to find your key :(")
