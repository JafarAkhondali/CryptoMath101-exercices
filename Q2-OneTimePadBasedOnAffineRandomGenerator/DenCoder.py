

import os
import re

import numpy as np
from copy import deepcopy
import random
from Helper import int2base, binaryStr, l, bitcount, calculate_max_bits_for_number, modinv
from math import ceil, floor
import configparser
from progress.bar import ChargingBar

class DenCoder:
    def __init__(self, alpha, beta, seed, mode):
        self.alpha= alpha
        self.beta = beta
        self.seed = seed
        self.mode = mode
        self.chunk_size = calculate_max_bits_for_number(mode)

    @staticmethod
    def save_key (file_object,alpha,beta,seed,mode):
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
        alpha = config.getint('key','alpha')
        beta = config.getint('key','beta')
        seed = config.getint('key','seed')
        mode = config.getint('key','mode')
        return DenCoder(alpha=alpha, beta=beta, seed=seed, mode=mode)


    def encryption_chunk_reader(self, file_name, chunk_size):
        with open(file_name, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if chunk:
                    yield chunk
                else: break

    def decryption_chunk_reader(self, filename, chunk_size):
        with open(filename, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if chunk:
                    yield chunk
                else: break

    def next_random_number(self):
        # while True:
        #     yield 0
        x = (self.alpha * self.seed + self.beta) % self.mode
        yield x
        while True:
            x = (self.alpha * x + self.beta) % self.mode
            yield x

    def encrypt_file(self, plaintext_file_name, ciphertext_file_name):
        pt_file = open(plaintext_file_name, "rb")  #self.encryption_chunk_reader(plaintext_file_name, chunk_size)
        ct_file = open(ciphertext_file_name, 'wb+')
        pt_bytes = pt_file.read()
        pt_data = int.from_bytes(pt_bytes, 'big')

        file_size = os.stat(plaintext_file_name).st_size
        bar = ChargingBar('[*] Encrypting ', max=((file_size*8 // self.chunk_size)))
        print((file_size*8 // self.chunk_size))
        random_generator = self.next_random_number()
        # bits_mask = 2 ** self.chunk_size - 1
        random_num = next(random_generator)

        pt_data = pt_data ^ random_num
        # pt_bits = pt_data & bits_mask
        # pt_data = pt_data >> self.chunk_size
        # ct_bits = (pt_bits ^ random_num) # | (ct_bits << self.chunk_size)
        # ct_bits=0
        # for _ in range(((file_size-self.chunk_size) // self.chunk_size)):
        for _ in range((file_size*8 // self.chunk_size)-1):
            # print(_)
            random_num = next(random_generator)
            pt_data ^= (random_num << (_+1) * self.chunk_size)
            # pt_data = pt_data >> self.chunk_size
            # ct_bits = (temp_bits ^  ) | (ct_bits << self.chunk_size)
            bar.next()
            # if _ % 100 == 0:
            #     print(index)
            #     bar.next()
        bar.next()
        # remaining_bits = (file_size*8 - ((_+2) * self.chunk_size))# % self.chunk_size
        # random_num = next(random_generator)
        # pt_bits = pt_data #& (2**remaining_bits-1)
        # last_block_xored = (pt_bits ^ random_num) & (2**remaining_bits-1)
        # ct_bits = ct_bits | last_block_xored
        # ct_bits = (ct_bits << remaining_bits ) | last_block_xored

        pt_data = pt_data.to_bytes(file_size, byteorder='big')
        # ct_bytes = ct_bits.to_bytes(file_size+floor(remaining_bits//8), byteorder='big')
        ct_file.write(pt_data)
        # ct_file.write(ct_bytes[0:file_size])
        bar.finish()
        l("Encryption done")
        l("Saved at %s" % os.path.abspath(ct_file.name))

    def decrypt_file(self, ciphertext_file_name, plaintext_file_name):
        pt_file = open(ciphertext_file_name, "rb")
        ct_file = open(plaintext_file_name, 'wb+')
        pt_bytes = pt_file.read()
        pt_data = int.from_bytes(pt_bytes, 'big')

        file_size = os.stat(ciphertext_file_name).st_size
        bar = ChargingBar('[*] Decrypting ', max=((file_size*8 // self.chunk_size)))
        print((file_size*8 // self.chunk_size))
        random_generator = self.next_random_number()
        random_num = next(random_generator)
        pt_data = pt_data ^ random_num
        for _ in range((file_size*8 // self.chunk_size)-1):
            random_num = next(random_generator)
            pt_data ^= (random_num << (_+1) * self.chunk_size)
            bar.next()
        bar.next()
        pt_data = pt_data.to_bytes(file_size, byteorder='big')
        ct_file.write(pt_data)
        bar.finish()
        l("Decryption done")
        l("Saved at %s" % os.path.abspath(pt_file.name))




    @staticmethod
    def extract_key(ciphertext_file,plaintext_file,key_file):
        PT_BYTES = open(plaintext_file,'rb').read()
        CT_BYTES = open(ciphertext_file,'rb').read()

        last_valid_block_size = -1
        last_valid_base_num = -1
        last_valid_padding_size = -1
        last_valid_lookup_table = dict()

        for padding_size in range(1,5):
            # padding = ct_file[0:padding_size]
            padding = CT_BYTES[0:padding_size]
            padding_length = int.from_bytes(padding, byteorder='little')

            print("-"*20)
            print("Cheking padding size: %s" % padding_size )
            # for block_size_bytes in range(1, 100):
            breaked = False
            for block_size_bytes in range(1,200):
                print("Cheking block_size : %s" % block_size_bytes)
                # for base_num in [9]:
                # for base_num in [3,5,6,7,8,9]:

                for base_num in range(2,10):
                    # l("Checking base_num: %s" % base_num )
                    #Read Cipher Block
                    biggest_number_in_block_base_10_len = len(str(int2base(2 ** (block_size_bytes * 8), base_num)))
                    max_block_size_after_encrypt_bits = len(binaryStr(int(str(base_num - 1) * biggest_number_in_block_base_10_len, base_num)))
                    max_block_size_after_encrypt_bytes = int(ceil(max_block_size_after_encrypt_bits / 8))

                    # print('MAX: %s' % max_block_size_after_encrypt_bytes)

                    shit = CT_BYTES[padding_size:padding_size+max_block_size_after_encrypt_bytes]

                    cipher_int_base_10 = int.from_bytes(shit , byteorder='little')

                    cipher_int = int2base(cipher_int_base_10, base_num)
                    block_size = max_block_size_after_encrypt_bytes * 8 - padding_length
                    zeros_count = block_size - len(bin(cipher_int_base_10)[2:])
                    cipher_block_in_base_n = zeros_count * '0' + cipher_int


                    #Read PlainText Block
                    plaintext_block_base_10 = int.from_bytes(PT_BYTES[0:block_size_bytes], byteorder='little')
                    plaintext_block_base_n = int2base(plaintext_block_base_10, base_num)
                    # print(plaintext_block_base_n)
                    # print(cipher_block_in_base_n)

                    # If two blocks are valid:
                    # 1. Their len must be same size
                    # 2. Dictionary generated by them should be valid for all numbers in block
                    if len(plaintext_block_base_n) != len(cipher_block_in_base_n):
                        continue
                    if last_valid_block_size < block_size_bytes :
                        is_lookup_table_valid, encryption_lookup_table = DenCoder.is_dictionary_valid(plaintext_block_base_n,cipher_block_in_base_n)
                        if is_lookup_table_valid:
                            last_valid_padding_size = padding_size
                            last_valid_base_num = base_num
                            last_valid_block_size = block_size_bytes
                            last_valid_lookup_table = encryption_lookup_table
                            # print("VALID: %s" % last_valid_block_size)
                # if breaked:
                #     break
        if last_valid_base_num == -1:
            exit("Unable to find a valid solution :(")

        print("Valid Base Number: %s" % last_valid_base_num)
        print("Valid Block Size: %s" % last_valid_block_size)
        while True:
            if len(last_valid_lookup_table) == last_valid_base_num:
                # We have all key -> value
                l("You are lucky bro, We found all values lookup table ")
                l(last_valid_lookup_table)
                break
            elif len(last_valid_lookup_table)+1 == last_valid_base_num:
                # Only one value is missing so we can find it using Proof behind
                l("There is only one value missing in our lookup table, but we can use Proof behind to find it :)")
                l("Current lookup table:")
                l(last_valid_lookup_table)
                all_keys = [str(x) for x in range(last_valid_base_num)]
                all_values = [str(x) for x in range(last_valid_base_num)]
                for index, key in enumerate(last_valid_lookup_table.keys()):
                    if key in last_valid_lookup_table:
                        all_values.remove(last_valid_lookup_table[key])
                        all_keys.remove(key)
                last_valid_lookup_table[all_keys[0]] = all_values[0]
                l("After finding missing value:")
                l(last_valid_lookup_table)
                break
            else:
                # More than one value is missing, We need to read another block
                l("We didn't get enough numbers to calculate valid key")
                l("Let's read another block")
                l(last_valid_lookup_table)
                biggest_number_in_block_base_10_len = len(
                    str(int2base(2 ** (last_valid_block_size * 8), last_valid_base_num)))
                max_block_size_after_encrypt_bits = len(binaryStr(
                    int(str(last_valid_base_num - 1) * biggest_number_in_block_base_10_len, last_valid_base_num)))
                max_block_size_after_encrypt_bytes = int(ceil(max_block_size_after_encrypt_bits / 8))

                cihper_reader_generator = range(last_valid_block_size+last_valid_padding_size,1000,max_block_size_after_encrypt_bytes+last_valid_padding_size)
                plain_reader_generator = range(last_valid_block_size,1000,last_valid_block_size)
                for decryptor_cursor, plain_cursor in zip(cihper_reader_generator, plain_reader_generator):
                    padding = CT_BYTES[decryptor_cursor:decryptor_cursor+last_valid_padding_size]
                    padding_length = int.from_bytes(padding, byteorder='little')



                    shit = CT_BYTES[decryptor_cursor:decryptor_cursor+max_block_size_after_encrypt_bytes]

                    cipher_int_base_10 = int.from_bytes(shit, byteorder='little')

                    cipher_int = int2base(cipher_int_base_10, last_valid_base_num)
                    block_size = max_block_size_after_encrypt_bytes * 8 - padding_length
                    zeros_count = block_size - len(bin(cipher_int_base_10)[2:])
                    cipher_block_in_base_n = zeros_count * '0' + cipher_int

                    # Read PlainText Block
                    plaintext_block_base_10 = int.from_bytes(PT_BYTES[plain_cursor:plain_cursor+last_valid_block_size], byteorder='little')
                    plaintext_block_base_n = int2base(plaintext_block_base_10, last_valid_base_num)
                    is_lookup_table_valid, last_valid_lookup_table = DenCoder.is_dictionary_valid(plaintext_block_base_n,cipher_block_in_base_n,last_valid_lookup_table)
                    if is_lookup_table_valid:
                        l("Something went wrong :(")
                        exit(-1)
                    if len(last_valid_lookup_table) +1 >= last_valid_base_num:
                        l("We've read enough blocks to crack")
                        break




        l("Now we have lookup table, Let's find a valid seed to generate look up table")
        valid_seed = None
        for seed in range(10000000000000000):
            test_lookup_table = DenCoder.generate_table(seed, last_valid_base_num, 'enc')
            if test_lookup_table == last_valid_lookup_table:
                l("Found a valid seed: %s" % seed)
                valid_seed = seed
                break
        if valid_seed is None:
            l("Sorry we were unable to find a valid seed :(")
        else:
            DenCoder.save_key(key_file, last_valid_base_num, valid_seed, last_valid_block_size)
