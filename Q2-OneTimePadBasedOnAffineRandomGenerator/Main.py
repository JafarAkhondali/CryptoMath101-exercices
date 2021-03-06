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
@click.option('--alpha', '-a', help='Mulitplier value for random generator', default=2)
@click.option('--beta', '-b', help='Bias value for random generator', default=1)
@click.option('--seed', '-s', help='Seed value for random generator', default=3)
@click.option('--mode', '-m', help='Mode value for random generator', default=13)
def generate_key(key_file,alpha,beta,seed,mode):
    l("Generating key file ...")
    DenCoder.save_key(key_file,alpha,beta,seed,mode)
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
@click.option('--mode-from', '-mf', help='Mode range value to check FROM', default=2)
@click.option('--mode-to', '-mt', help='Mode range value to check TO', default=20)
@click.option('--key-file', '-k', help='Generated key file to use in encryption', default='key.config', type=click.File('w+'))
def crack(ciphertext_file,plaintext_file,mode_from,mode_to,key_file):
    if mode_to < mode_from:
        print("MODE_TO should be higher than MODE_FROM!")
        exit(-1)
    if mode_from < 2:
        print("Mode FROM range should be higher than 2!")
        exit(-2)
    DenCoder.extract_key(ciphertext_file,plaintext_file,mode_from,mode_to,key_file)


cli.add_command(generate_key)
cli.add_command(encrypt)
cli.add_command(decrypt)
cli.add_command(crack)

if __name__ == '__main__':
    cli()
