import click
import sys
from DenCoder import DenCoder
import random
from Helper import l, is_prime
import os
import random

MIN_32_BITS = 1 << 31
MAX_32_BITS = (1 << 32) - 1


@click.group()
def cli():
    pass


@click.command("gen")
@click.option('--key-file', '-k', help='Generated key file to use in encryption', default='key.config',
              type=click.File('w+'))
@click.option('--alpha', '-a', help='Mulitplier value for Affine', default=5)
@click.option('--beta', '-b', help='Bias value for Affine', default=3)
@click.option('--primes', '-p', help='Prime numbers seperated by `,`. Ex: 17,19,181', default=None)
@click.option('--primes-count', '-pcount', help='Exact count of primes', default=None)
@click.option('--primes-count-min-range', '-pmin', help='Minimum value for count of primes', default=2)
@click.option('--primes-count-max-range', '-pmax', help='Maximum value for count of primes', default=5)
def generate_key(key_file, alpha, beta, primes, primes_count, primes_count_min_range, primes_count_max_range):
    l("Generating key file ...")

    if alpha >= MIN_32_BITS:
        raise click.UsageError("Alpha is in range of 32bit numbers!")

    primes_list = []
    # Unless user specifies primes, We'll have to pick random numbers in range 32bits
    if primes:
        primes_list = [int(p) for p in primes.split(',')]
        for p in primes_list:
            if not is_prime(p):
                raise click.UsageError("Dude %d is not a prime number :|" % p)
    else:
        primes_count = primes_count if primes_count else random.randrange(primes_count_min_range, primes_count_max_range)

        l("Generating %d primes in range of 32bits, Please wait..." % primes_count)
        primes_list = []
        while len(primes_list) < primes_count:
            rand_32_int = random.randrange(MIN_32_BITS, MAX_32_BITS) | 1  # Only use odd numbers
            if is_prime(rand_32_int):
                primes_list.append(rand_32_int)
        print("Chosed primes: " + str(primes_list))
    DenCoder.save_key(key_file, alpha, beta, primes_list)
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


@click.command("crack")
@click.option('--ciphertext-file', '-ct', help='Ciphertext or any ciphered file', default='ciphertext.enc',
              type=click.Path(readable=True, exists=True))
@click.option('--plaintext-file', '-pt', help='Plaintext or any unciphered file', default='plaintext.txt',
              type=click.Path(readable=True, exists=True))
@click.option('--mode-from', '-mf', help='Mode range value to check FROM', default=2)
@click.option('--mode-to', '-mt', help='Mode range value to check TO', default=20)
@click.option('--key-file', '-k', help='Generated key file to use in encryption', default='key.config',
              type=click.File('w+'))
def crack(ciphertext_file, plaintext_file, mode_from, mode_to, key_file):
    if mode_to < mode_from:
        print("MODE_TO should be higher than MODE_FROM!")
        exit(-1)
    if mode_from < 2:
        print("Mode FROM range should be higher than 2!")
        exit(-2)
    DenCoder.extract_key(ciphertext_file, plaintext_file, mode_from, mode_to, key_file)


cli.add_command(generate_key)
cli.add_command(encrypt)
cli.add_command(decrypt)
cli.add_command(crack)

if __name__ == '__main__':
    cli()
