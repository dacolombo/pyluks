#! /usr/bin/env python3
import fastluks
import argparse

#______________________________________
def cli_options():
    parser = argparse.ArgumentParser(description='fastluks main script')
    parser.add_argument('--device', default='/dev/vdb',dest='device_name', help='Device')
    parser.add_argument('--cryptdev', default='crypt', dest='cryptdev', help='Cryptdev')
    parser.add_argument('-m', '--mountpoint', default='/export', dest='mountpoint', help='Cryptdev mountpoint')
    parser.add_argument('-f', '--filesystem', default='ext4', dest='filesystem', help='Device filesystem')
    parser.add_argument('-c', '--cipher', default='aes-xts-plain64', dest='cipher_algorithm', help='Cipher algorithm')
    parser.add_argument('-s', '--key-size', default=256, type=int, dest='keysize', help='Key size')
    parser.add_argument('--hash', default='sha256', dest='hash_algorithm', help='Hash algorithm')
    parser.add_argument('--header-backup-dir', default='/etc/luks', dest='luks_header_backup_dir', help='LUKS header backup dir')
    parser.add_argument('--header-backup-file', default='luks-header.bck', dest='luks_header_backup_file', help='LUKS header backup file')
    parser.add_argument('--cryptdev-file', default='/etc/luks/luks-cryptdev.ini', dest='luks_cryptdev_file', help='LUKS cryptdev ini file')
    parser.add_argument('-l', '--passphrase-length', default=8, type=int, dest='passphrase_length', help='Passphrase length')
    parser.add_argument('-p', '--passphrase', default=None, dest='passphrase', help='Passphrase')
    parser.add_argument('--passphrase_confirmation', default=None, dest='passphrase_confirmation', help='Passphrase confirmation')
    return parser.parse_args()

#______________________________________
def encrypt_and_setup():

    options = cli_options()

    fastluks.main_script(options.device_name, options.cryptdev, options.mountpoint, options.filesystem,
                        options.cipher_algorithm, options.keysize, options.hash_algorithm,
                        options.luks_header_backup_dir, options.luks_header_backup_file, options.luks_cryptdev_file,
                        options.passphrase_length, options.passphrase, options.passphrase_confirmation)

#______________________________________
if __name__ == '__main__':
    encrypt_and_setup()