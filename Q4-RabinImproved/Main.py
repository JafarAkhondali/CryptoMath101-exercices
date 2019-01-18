import click
import sys
from DenCoder import DenCoder
import random
from Helper import l, is_prime
import os
import random


@click.group()
def cli():
    pass


@click.command("gen")
@click.option('--key-file', '-k', help='Generated key file to use in encryption', default='key.config',
              type=click.File('w+'))
@click.option('--count-of-bits', '-n', help='Count of bits to use when calculating p,q', default=32)
def generate_key(key_file, count_of_bits):
    l("Generating p,q primes in range of 32bits, Please wait...")
    MIN_RANGE_NUMBER = 1 << count_of_bits
    MAX_RANGE_NUMBER = (1 << (count_of_bits+1)) - 1

    primes_list = []
    while len(primes_list) < 2:
        rand_32_int = random.randrange(MIN_RANGE_NUMBER, MAX_RANGE_NUMBER ) | 11  # We only want numbers % 4 == 3, So we'll modify their lower bits to 3
        if rand_32_int not in primes_list and is_prime(rand_32_int):
            primes_list.append(rand_32_int)
    print("Chosen primes: " + str(primes_list))
    p,q = sorted(primes_list)
    DenCoder.save_key(key_file, p, q)
    l("Key file generated at %s" % (os.path.realpath(key_file.name)))


@click.command("enc")
@click.option('--key-file', '-k', help='Generated key file to use in encryption', default='key.config',
              type=click.Path(exists=True, readable=True))
@click.option('--plaintext-file', '-pt', help='Plaintext or any unciphered file', default='plaintext.txt',
              type=click.Path(exists=True, readable=True))
@click.option('--ciphertext-file', '-ct', help='Ciphertext or any ciphered file', default='ciphertext.enc',
              type=click.Path(writable=True))
def encrypt(key_file, plaintext_file, ciphertext_file):
    l("Parsing key file")
    denCoder = DenCoder.read_key(open(key_file))
    denCoder.encrypt_file(plaintext_file, ciphertext_file)


@click.command("dec")
@click.option('--key-file', '-k', help='Generated key file to use in encryption', default='key.config',
              type=click.Path(exists=True, readable=True))
@click.option('--ciphertext-file', '-ct', help='Ciphertext or any ciphered file', default='ciphertext.enc',
              type=click.Path(readable=True, exists=True))
@click.option('--plaintext-file', '-pt', help='Plaintext or any unciphered file', default='plaintext.txt',
              type=click.Path(writable=True))
def decrypt(key_file, ciphertext_file, plaintext_file):
    l("Parsing key file")
    den_coder = DenCoder.read_key(open(key_file))
    den_coder.decrypt_file(ciphertext_file, plaintext_file)


cli.add_command(generate_key)
cli.add_command(encrypt)
cli.add_command(decrypt)

if __name__ == '__main__':
    cli()
