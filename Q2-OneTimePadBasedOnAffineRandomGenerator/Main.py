import click
import sys
from DenCoder import DenCoder
import random
from Helper import l
import os

@click.group()
def cli():
    pass





@click.command("gen")
@click.option('--key-file', '-k', help='Generated key file to use in encryption', default='key.config', type=click.File('w+'))
@click.option('--alpha-num', '-a', help='Alpha number in ', default=7)
@click.option('--block-size-bytes', '-bs', help='Block size for reading plaintext bytes', default=20)
def generate_key(key_file,base_num,block_size_bytes):
    l("Generating key file ...")
    seed = random.random()
    #den_coder = DenCoder(base_num=base_num, seed=seed, block_size_bytes=block_size_bytes)
    DenCoder.save_key(key_file, base_num=base_num, seed=seed, block_size_bytes=block_size_bytes)
    l("Key file generated at %s" % (os.path.realpath(key_file.name)))


@click.command("enc")
@click.option('--key-file', '-k', help='Generated key file to use in encryption', default='key.config', type=click.Path(exists=True,readable=True))
@click.option('--plaintext-file', '-pt',help='Plaintext or any unciphered file', default='plaintext.txt', type=click.Path(exists=True,readable=True))
@click.option('--ciphertext-file', '-ct',help='Ciphertext or any ciphered file', default='ciphertext.enc', type=click.Path(writable=True))
def encrypt(key_file, plaintext_file, ciphertext_file):
    l("Parsing key file")
    denCoder = DenCoder.read_key(open(key_file))
    denCoder.encrypt_file(plaintext_file,ciphertext_file)


@click.command("dec")
@click.option('--key-file', '-k', help='Generated key file to use in encryption', default='key.config', type=click.Path(exists=True,readable=True))
@click.option('--ciphertext-file', '-ct',help='Ciphertext or any ciphered file', default='ciphertext.enc', type=click.Path(readable=True,exists=True))
@click.option('--plaintext-file', '-pt',help='Plaintext or any unciphered file', default='plaintext.txt', type=click.Path(writable=True))
def decrypt(key_file,ciphertext_file,plaintext_file):
    l("Parsing key file")
    den_coder = DenCoder.read_key(open(key_file))
    den_coder.decrypt_file(ciphertext_file,plaintext_file)


@click.command("crack")
@click.option('--ciphertext-file', '-ct',help='Ciphertext or any ciphered file', default='ciphertext.enc', type=click.Path(readable=True,exists=True))
@click.option('--plaintext-file', '-pt',help='Plaintext or any unciphered file', default='plaintext.txt', type=click.Path(readable=True,exists=True))
@click.option('--key-file', '-k', help='Generated key file to use in encryption', default='key.config', type=click.File('w+'))
def crack(ciphertext_file,plaintext_file,key_file):
    DenCoder.extract_key(ciphertext_file,plaintext_file,key_file)


cli.add_command(generate_key)
cli.add_command(encrypt)
cli.add_command(decrypt)
cli.add_command(crack)

if __name__ == '__main__':
    cli()


# def Gen(key_file, plaintext_file, ciphertext_file):
#     """
#     Ex to generate a key: \n
#     python Main.py gen -k mykey.key
#     """
#     print("I'm a beautiful CLI ✨")