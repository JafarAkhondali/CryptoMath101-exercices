import os
import re

import numpy as np
from copy import deepcopy
import random
from Helper import int2base, binaryStr, l, bitcount, calculate_max_bits_for_number, modinv, egcd
from math import ceil, floor
import configparser
from progress.bar import ChargingBar


class DenCoder:
    def __init__(self, alpha, beta, seed, mode):
        self.alpha = alpha
        self.beta = beta
        self.seed = seed
        self.mode = mode
        self.chunk_size = calculate_max_bits_for_number(mode)

    @staticmethod
    def save_key(file_object, alpha, beta, seed, mode):
        config = configparser.ConfigParser()
        config['key'] = {
            'alpha': alpha,
            'beta': beta,
            'seed': seed,
            'mode': mode
        }
        config.write(file_object)

    @staticmethod
    def read_key(file_object):
        config = configparser.ConfigParser()
        config.read_file(file_object)
        alpha = config.getint('key', 'alpha')
        beta = config.getint('key', 'beta')
        seed = config.getint('key', 'seed')
        mode = config.getint('key', 'mode')
        return DenCoder(alpha=alpha, beta=beta, seed=seed, mode=mode)

    def next_random_number(self):
        # while True:
        #     yield 0
        x = (self.alpha * self.seed + self.beta) % self.mode
        yield x
        while True:
            x = (self.alpha * x + self.beta) % self.mode
            yield x

    def encrypt_file(self, plaintext_file_name, ciphertext_file_name):
        pt_file = open(plaintext_file_name, "rb")
        ct_file = open(ciphertext_file_name, 'wb+')
        pt_bytes = pt_file.read()
        pt_data = int.from_bytes(pt_bytes, 'big')

        file_size = os.stat(plaintext_file_name).st_size
        bar = ChargingBar('[*] Encrypting ', max=((file_size * 8 // self.chunk_size)))
        random_generator = self.next_random_number()
        random_num = next(random_generator)

        pt_data = pt_data ^ random_num
        bar.next()

        for _ in range((file_size * 8 // self.chunk_size) - 1):
            random_num = next(random_generator)
            pt_data ^= (random_num << (_ + 1) * self.chunk_size)
            bar.next()
        bar.next()
        pt_data = pt_data.to_bytes(file_size, byteorder='big')
        ct_file.write(pt_data)
        bar.finish()
        l("Encryption done")
        l("Saved at %s" % os.path.abspath(ct_file.name))

    def decrypt_file(self, ciphertext_file_name, plaintext_file_name):
        pt_file = open(ciphertext_file_name, "rb")
        ct_file = open(plaintext_file_name, 'wb+')
        pt_bytes = pt_file.read()
        pt_data = int.from_bytes(pt_bytes, 'big')

        file_size = os.stat(ciphertext_file_name).st_size
        bar = ChargingBar('[*] Decrypting ', max=((file_size * 8 // self.chunk_size)))
        random_generator = self.next_random_number()
        random_num = next(random_generator)
        pt_data = pt_data ^ random_num
        for _ in range((file_size * 8 // self.chunk_size) - 1):
            random_num = next(random_generator)
            pt_data ^= (random_num << (_ + 1) * self.chunk_size)
            bar.next()
        bar.next()
        pt_data = pt_data.to_bytes(file_size, byteorder='big')
        ct_file.write(pt_data)
        bar.finish()
        l("Decryption done")
        l("Saved at %s" % os.path.abspath(ct_file.name))

    @staticmethod
    def affinehill(alpha, beta, x, mode, val):
        c = (alpha * x + beta) % mode
        if c == val:
            return True
        raise Exception("Not possible: %s != %s" % (c,val))

    @staticmethod
    def extract_key(ciphertext_file, plaintext_file, mode_from, mode_to, key_file):
        PT_DATA = int.from_bytes(open(plaintext_file, 'rb').read(), 'big')
        CT_DATA = int.from_bytes(open(ciphertext_file, 'rb').read(), 'big')

        l("Starting key extraction")
        alpha = beta = seed = mode = 0
        found_key = False
        for mode in range(mode_from, mode_to + 1):
            chunk_size = calculate_max_bits_for_number(mode)

            P1_HILL = PT_DATA & (2**chunk_size - 1)
            C1 = CT_DATA & (2**chunk_size - 1)

            P2_HILL = (PT_DATA >> chunk_size) & (2 ** chunk_size - 1)
            C2 = (CT_DATA >> chunk_size) & (2 ** chunk_size- 1)

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

                gcd, __, ___ = egcd((X3 - X4)%mode, mode)

                gcd_flag = False
                if gcd != 1:
                    alpha = ( (((X4 - X5)%mode)//gcd) * modinv(((X3 - X4)%mode) // gcd, mode // gcd)) % (mode // gcd)
                    gcd_flag = True
                else:
                    alpha = (((X4 - X5)%mode) * modinv((X3 - X4)%mode, mode)) % mode

                if gcd_flag:
                    for alpha_test in range(alpha, mode + 1, gcd):
                        try:
                            # alpha * X1 + beta % mode = X2
                            # beta % mode = X2 - alpha * X1
                            beta = (X3 - (alpha_test * X2)%mode ) % mode

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
