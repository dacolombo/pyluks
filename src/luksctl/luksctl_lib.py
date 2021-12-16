# import dependencies
import os, sys
import logging
from configparser import ConfigParser

# Import internal dependencies
from fastluks import run_command

#______________________________________
# Log config
#from .common_logging import set_log
#logs = set_log('/tmp/luksctl.log', 'DEBUG')
logging.basicConfig(filename='/tmp/luksctl.log', filemode='a+', level=0, format='%(levelname)s %(asctime)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

#______________________________________
class LUKSCtl:
    def __init__(self, fname):

        self.fname = fname

        config = ConfigParser()
        config.read_file(open(fname))

        self.cipher_algorithm = config.get('luks', 'cipher_algorithm')
        self.hash_algorithm = config.get('luks', 'hash_algorithm')
        self.keysize = config.get('luks', 'keysize')
        self.device = config.get('luks', 'device')
        self.uuid = config.get('luks', 'uuid')
        self.cryptdev = config.get('luks', 'cryptdev')
        self.mapper = config.get('luks', 'mapper')
        self.mountpoint = config.get('luks', 'mountpoint')
        self.filesystem = config.get('luks', 'filesystem')

    #______________________________________
    # getter
    def get_cipher_algorithm(self): return self.cipher_algorithm
    def get_hash_algorithm(self): return self.hash_algorithm
    def get_keysize(self): return self.keysize
    def get_device(self): return self.device
    def get_uuid(self): return self.uuid
    def get_cryptdev(self): return self.cryptdev
    def get_mapper(self): return self.mapper
    def get_mountpoint(self): return self.mountpoint
    def get_filesystem(self): return self.filesystem

    #______________________________________
    # setter
    def set_cipher_algorithm(self, cipher_algorithm): self.cipher_algorithm = cipher_algorithm
    def set_hash_algorithm(self, hash_algorithm): self.hash_algorithm = hash_algorithm
    def set_keysize(self, keysize): keysize = keysize
    def set_device(self, device): self.device = device
    def set_uuid(self, uuid): self.uuid = uuid
    def set_cryptdev(self, cryptdev): self.cryptdev = cryptdev
    def set_mapper(self, mapper): self.mapper = mapper
    def set_mountpoint(self, mountpoint): self.mountpoint = mountpoint
    def set_filesystem(self, filesystem): self.filesystem = filesystem

    #____________________________________
    # dmsetup info
    def dmsetup_info(self):
        _, _, status = run_command(f'dmsetup info /dev/mapper/{self.cryptdev}')
        return status
  
    #____________________________________
    # Display dmsetup info
    def display_dmsetup_info(self):
        stdOutValue, stdErrValue, status = run_command(f'dmsetup info /dev/mapper/{self.cryptdev}')
    
        if str(status) == '0':
            print(stdOutValue)
            print('Encrypted volume: [ OK ]')
            sys.exit(0)
        else:
            logging.error(f'[luksctl] {stdErrValue}')
            print('Encrypted volume: [ FAIL ]')
            sys.exit(1)
    
    #______________________________________
    # luksOpen device
    def luksopen_device(self):
        run_command(f'cryptsetup luksOpen /dev/disk/by-uuid/{self.uuid} {self.cryptdev}')
    
        _, _, status = run_command(f'mount /dev/mapper/{self.cryptdev} {self.mountpoint}')
    
        if str(status) == '0':
            os.system(f'chown galaxy:galaxy {self.mountpoint}')
            self.display_dmsetup_info()
        else:
            print('Encrypted volume mount: [ FAIL ]')
            sys.exit(1)
    
    #______________________________________
    # luksClose device
    def luksclose_device(self):
        run_command(f'umount {self.mountpoint}') # Unmount device
    
        run_command(f'cryptsetup close {self.cryptdev}') # Close device
    
        # if dmsetup_setup fails (status 1) the volume has been correctly closed
        if str(self.dmsetup_info()) == '0':
            print('Encrypted volume umount: [ FAIL ]')
            sys.exit(1)
        else:
            print('Encrypted volume umount: [ OK ]')
            sys.exit(0)