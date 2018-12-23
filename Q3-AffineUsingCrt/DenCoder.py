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
        self.chunk_size = (self.mode.bit_length()-1) // 8

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
            cts=[]
            for p in self.primes:
                small_p = (chunk % p)
                small_cipher = (self.alpha * small_p + self.beta) % p
                cts.append(small_cipher)

            for i, ct in enumerate(cts):
                x = ct.to_bytes(PRIME_SIZE, byteorder='little')
                ct_file.write(x)
            bar.next()
        bar.finish()
        l("Encryption done")
        l("Saved at %s" % os.path.abspath(ct_file.name))

    def decrypt_file(self, ciphertext_file_name, plaintext_file_name):
        ct_file = open(ciphertext_file_name, "rb")
        pt_file = open(plaintext_file_name, 'wb+')
        file_size = os.stat(ciphertext_file_name).st_size
        count_of_primes = len(self.primes)
        bar = ChargingBar('[*] Decrypting ', max=(file_size // self.chunk_size) - 1)

        # Read cipher text chunk
        cts = []
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
    def extract_key(ciphertext_file, plaintext_file, primes, key_file):

        count_of_primes = len(primes)
        l("Starting key extraction")
        found_key = False
        calpha = cbeta = None
        for alpha in range(1, 100):
            if found_key:
                break
            for beta in range(0, 100):
                if found_key:
                    break
                l("Checking Alpha= %s \tBeta= %s" % (alpha, beta))
                try:
                    pt_file = open(plaintext_file, 'rb')
                    ct_file = open(ciphertext_file, 'rb')

                    fakecoder = DenCoder(0, 0, primes)
                    encrypt_reader_generator = fakecoder.encryption_chunk_reader(pt_file, fakecoder.chunk_size)
                    decrypt_reader_generator = fakecoder.decryption_chunk_reader(ct_file, PRIME_SIZE,
                                                                                 fakecoder.chunk_size)
                    enc_chunk = next(encrypt_reader_generator)
                    enc_cts = []
                    for p in primes:
                        small_p = (enc_chunk % p)
                        small_cipher = (alpha * small_p + beta) % p
                        enc_cts.append(small_cipher)

                    dec_cts = []
                    for i, (dec_chunk, chunk_size) in enumerate(decrypt_reader_generator):
                        chunk = ((dec_chunk - beta) * modinv(alpha, primes[i % count_of_primes])) % primes[i % count_of_primes]
                        dec_cts.append(chunk)
                        if len(dec_cts) < count_of_primes:
                            continue
                        ct = solve_crt(dec_cts, primes)
                        dec_cts = []
                        break

                    if ct == enc_chunk:
                        l("Found key: valid Alpha=%s \tBeta=%s " % (alpha, beta))
                        calpha = alpha
                        cbeta = beta
                        found_key = True
                        break
                    else:
                        continue
                except Exception as e:
                    continue
        if not found_key:
            l("Sorry i wasn't able to find your key :(")
        else:
            DenCoder.save_key(key_file, calpha, cbeta, primes)
            l("Key file generated at %s" % (os.path.realpath(key_file.name)))