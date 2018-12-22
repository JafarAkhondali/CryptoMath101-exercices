import os
import re

import numpy as np
from copy import deepcopy
import random
from Helper import int2base, binaryStr, l, bitcount
from math import ceil
import configparser
from progress.bar import ChargingBar


class DenCoder:
    def __init__(self, base_num, seed, block_size_bytes):
        self.base_num = base_num
        self.seed = seed
        self.block_size_bytes = block_size_bytes

        # Generate lookUpTable
        keys = np.arange(base_num)
        values = deepcopy(keys)

        if seed:
            random.seed(seed)

        random.shuffle(values)
        self.look_up_table_encryption = {str(key): str(value) for (key, value) in zip(keys, values)}
        self.look_up_table_decryption = {str(key): str(value) for (key, value) in zip(values, keys)}
        l(self.look_up_table_encryption)
        # Generate lookUpTable
        # self.look_up_table_encryption = DenCoder.generate_table(seed,base_num,'enc')
        # self.look_up_table_decryption = DenCoder.generate_table(seed,base_num,'dec')

        biggest_number_in_block_base_10_len = len(str(int2base(2 ** (block_size_bytes * 8), base_num)))

        # Calculate block padding
        self.max_block_size_after_encrypt_bits = len(
            binaryStr(int(str(base_num - 1) * biggest_number_in_block_base_10_len, base_num)))
        self.max_block_size_after_encrypt_bytes = int(ceil(self.max_block_size_after_encrypt_bits / 8))
        self.max_block_size_after_encrypt_bits = self.max_block_size_after_encrypt_bytes * 8
        self.padding_block_size_bytes = self.calculate_padding_length(self.max_block_size_after_encrypt_bits)

    @staticmethod
    def save_key(file_object, base_num, seed, block_size_bytes):
        config = configparser.ConfigParser()
        config['key'] = {
            'p': base_num,
            'seed': seed,
            'block_size_bytes': block_size_bytes
        }
        config.write(file_object)

    @staticmethod
    def read_key(file_object):
        config = configparser.ConfigParser()
        config.read_file(file_object)
        base_num = config.getint('key', 'p')
        seed = config.getfloat('key', 'seed')
        block_size_bytes = config.getint('key', 'block_size_bytes')
        return DenCoder(base_num=base_num, seed=seed, block_size_bytes=block_size_bytes)

    def print_lookup_table(self):
        l(self.look_up_table_encryption)

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

    def encryption_chunk_reader(self, file_name, chunk_size):
        with open(file_name, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if chunk:
                    yield chunk
                else:
                    break

    # def decryption_chunk_reader(self, filename, padding_size, base_destination,max_block_size_after_encrypt_bytes, block_size_bytes):
    def decryption_chunk_reader(self, filename, padding_size, base_destination):
        file_size = os.stat(filename).st_size
        with open(filename, "rb") as f:
            while True:
                padding = f.read(padding_size)
                if not padding:
                    break
                padding_length = int.from_bytes(padding, byteorder='little')
                cipher_int_base_10 = int.from_bytes(f.read(self.max_block_size_after_encrypt_bytes), byteorder='little')
                cipher_int = int2base(cipher_int_base_10, base_destination)
                block_size = self.max_block_size_after_encrypt_bytes * 8 - padding_length
                zeros_count = block_size - len(bin(cipher_int_base_10)[2:])
                chunk = zeros_count * '0' + cipher_int
                chunk_size = self.block_size_bytes
                if f.tell() < file_size:
                    yield chunk, chunk_size
                else:
                    yield chunk, ((block_size + zeros_count) // 8) + 1
                    break
                # if chunk:
                # yield chunk, ceil(block_size/8) + zeros_count

                # yield chunk, len(chunk)
                # else:
                #     break

    def encrypt_file(self, plaintext_file_name, ciphertext_file_name):
        pt_file = self.encryption_chunk_reader(plaintext_file_name, self.block_size_bytes)
        ct_file = open(ciphertext_file_name, 'wb+')

        file_size = os.stat(plaintext_file_name).st_size
        bar = ChargingBar('[*] Encrypting ', max=(file_size // (self.block_size_bytes * 100)) + 1)
        for index, pt_chunk in enumerate(pt_file):
            if index % 100 == 0:
                bar.next()
            plain_num_base_10 = int.from_bytes(pt_chunk, byteorder='little')
            # print(self.block_size_bytes)
            nums_after_lookup_table = ''
            # temp = ''
            for num in int2base(plain_num_base_10, self.base_num):
                # temp += num
                nums_after_lookup_table = nums_after_lookup_table + self.look_up_table_encryption.get(num)
            # print('PT: %s' % temp)
            # print('CT: %s' % nums_after_lookup_table )

            leading_zero_bytes = re.search('(?!0)', nums_after_lookup_table).start()
            nums_after_lookup_table = int(nums_after_lookup_table, self.base_num)
            padding_bits = self.max_block_size_after_encrypt_bits - len(
                bin(nums_after_lookup_table)[2:]) - leading_zero_bytes
            padding_bytes = padding_bits.to_bytes(self.padding_block_size_bytes, byteorder='little')
            # print('------')
            ct_bytes = nums_after_lookup_table.to_bytes(self.max_block_size_after_encrypt_bytes, byteorder='little')
            ct_file.write(padding_bytes)
            ct_file.write(ct_bytes)
        bar.finish()
        l("Encryption done")
        l("Saved at %s" % os.path.abspath(ct_file.name))

    def decrypt_file(self, ciphertext_file_name, plaintext_file_name):
        # filename, chunk_size, padding_size, base_destination):
        ct_chunk_reader = self.decryption_chunk_reader(ciphertext_file_name, self.padding_block_size_bytes,
                                                       self.base_num)
        # ct_chunk_reader = self.decryption_chunk_reader(ciphertext_file_name) #, self.padding_block_size_bytes, self.base_num, self.max_block_size_after_encrypt_bytes, self.block_size_bytes )
        pt_file = open(plaintext_file_name, 'wb+')
        file_size = os.stat(ciphertext_file_name).st_size

        bar = ChargingBar('[*] Decrypting ', max=(file_size // (self.max_block_size_after_encrypt_bytes * 1000)) + 1)
        for index, (pt_chunk, block_size) in enumerate(ct_chunk_reader):
            if index % 1000 == 0:
                bar.next()
            nums_after_lookup_table = ''
            for num in pt_chunk:
                nums_after_lookup_table = nums_after_lookup_table + self.look_up_table_decryption.get(num)
            nums_after_lookup_table = int(nums_after_lookup_table, self.base_num)
            # if len(bin(nums_after_lookup_table)[2:])/8 > block_size:
            #     someshit=1
            ct_bytes = nums_after_lookup_table.to_bytes(block_size, byteorder='little')
            # ct_bytes = nums_after_lookup_table.to_bytes(self.block_size_bytes, byteorder='little')
            pt_file.write(ct_bytes)
            # except Exception as e:
            #     print(e)
            #     pass
        bar.next(bar.max - bar.index)
        bar.finish()
        l("Decryption done")
        l("Saved at %s" % os.path.abspath(pt_file.name))

    @staticmethod
    def extract_key(ciphertext_file, plaintext_file, key_file):
        PT_BYTES = open(plaintext_file, 'rb').read()
        CT_BYTES = open(ciphertext_file, 'rb').read()

        last_valid_block_size = -1
        last_valid_base_num = -1
        last_valid_padding_size = -1
        last_valid_lookup_table = dict()

        for padding_size in range(1, 5):
            # padding = ct_file[0:padding_size]
            padding = CT_BYTES[0:padding_size]
            padding_length = int.from_bytes(padding, byteorder='little')

            print("-" * 20)
            print("Cheking padding size: %s" % padding_size)
            # for block_size_bytes in range(1, 100):
            breaked = False
            for block_size_bytes in range(1, 200):
                print("Cheking block_size : %s" % block_size_bytes)
                # for base_num in [9]:
                # for base_num in [3,5,6,7,8,9]:

                for base_num in range(2, 10):
                    # l("Checking base_num: %s" % base_num )
                    # Read Cipher Block
                    biggest_number_in_block_base_10_len = len(str(int2base(2 ** (block_size_bytes * 8), base_num)))
                    max_block_size_after_encrypt_bits = len(
                        binaryStr(int(str(base_num - 1) * biggest_number_in_block_base_10_len, base_num)))
                    max_block_size_after_encrypt_bytes = int(ceil(max_block_size_after_encrypt_bits / 8))

                    # print('MAX: %s' % max_block_size_after_encrypt_bytes)

                    shit = CT_BYTES[padding_size:padding_size + max_block_size_after_encrypt_bytes]

                    cipher_int_base_10 = int.from_bytes(shit, byteorder='little')

                    cipher_int = int2base(cipher_int_base_10, base_num)
                    block_size = max_block_size_after_encrypt_bytes * 8 - padding_length
                    zeros_count = block_size - len(bin(cipher_int_base_10)[2:])
                    cipher_block_in_base_n = zeros_count * '0' + cipher_int

                    # Read PlainText Block
                    plaintext_block_base_10 = int.from_bytes(PT_BYTES[0:block_size_bytes], byteorder='little')
                    plaintext_block_base_n = int2base(plaintext_block_base_10, base_num)
                    # print(plaintext_block_base_n)
                    # print(cipher_block_in_base_n)

                    # If two blocks are valid:
                    # 1. Their len must be same size
                    # 2. Dictionary generated by them should be valid for all numbers in block
                    if len(plaintext_block_base_n) != len(cipher_block_in_base_n):
                        continue
                    if last_valid_block_size < block_size_bytes:
                        is_lookup_table_valid, encryption_lookup_table = DenCoder.is_dictionary_valid(
                            plaintext_block_base_n, cipher_block_in_base_n)
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
            elif len(last_valid_lookup_table) + 1 == last_valid_base_num:
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

                cihper_reader_generator = range(last_valid_block_size + last_valid_padding_size, 1000,
                                                max_block_size_after_encrypt_bytes + last_valid_padding_size)
                plain_reader_generator = range(last_valid_block_size, 1000, last_valid_block_size)
                for decryptor_cursor, plain_cursor in zip(cihper_reader_generator, plain_reader_generator):
                    padding = CT_BYTES[decryptor_cursor:decryptor_cursor + last_valid_padding_size]
                    padding_length = int.from_bytes(padding, byteorder='little')

                    shit = CT_BYTES[decryptor_cursor:decryptor_cursor + max_block_size_after_encrypt_bytes]

                    cipher_int_base_10 = int.from_bytes(shit, byteorder='little')

                    cipher_int = int2base(cipher_int_base_10, last_valid_base_num)
                    block_size = max_block_size_after_encrypt_bytes * 8 - padding_length
                    zeros_count = block_size - len(bin(cipher_int_base_10)[2:])
                    cipher_block_in_base_n = zeros_count * '0' + cipher_int

                    # Read PlainText Block
                    plaintext_block_base_10 = int.from_bytes(
                        PT_BYTES[plain_cursor:plain_cursor + last_valid_block_size], byteorder='little')
                    plaintext_block_base_n = int2base(plaintext_block_base_10, last_valid_base_num)
                    is_lookup_table_valid, last_valid_lookup_table = DenCoder.is_dictionary_valid(
                        plaintext_block_base_n, cipher_block_in_base_n, last_valid_lookup_table)
                    if is_lookup_table_valid:
                        l("Something went wrong :(")
                        exit(-1)
                    if len(last_valid_lookup_table) + 1 >= last_valid_base_num:
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

    @staticmethod
    def is_dictionary_valid(plaintext_block_base_n, cipher_block_in_base_n, plain_lookup_table=None):
        if not plain_lookup_table:
            plain_lookup_table = {}

        for index, num in enumerate(plaintext_block_base_n):
            if num in plain_lookup_table:
                if plain_lookup_table[num] != cipher_block_in_base_n[index]:
                    return False, plain_lookup_table
            else:
                plain_lookup_table[num] = cipher_block_in_base_n[index]
        return True, plain_lookup_table

    @staticmethod
    def generate_table(seed, base_num, type):
        random.seed(seed)
        keys = np.arange(base_num)
        values = deepcopy(keys)
        random.shuffle(values)
        return {str(key): str(value) for (key, value) in zip(keys, values)} if type == 'enc' else {str(key): str(value)
                                                                                                   for (key, value) in
                                                                                                   zip(values, keys)}
