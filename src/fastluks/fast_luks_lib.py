# import dependencies
import logging
import random
from string import ascii_letters, digits, ascii_lowercase
import subprocess
import os
from pathlib import Path
from datetime import datetime
import re
import zc.lockfile
from configparser import ConfigParser
import requests
# https://stackoverflow.com/questions/27981545/suppress-insecurerequestwarning-unverified-https-request-is-being-made-in-pytho
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import json

################################################################################
# VARIABLES
alphanum = ascii_letters + digits
LOGFILE = '/tmp/fast_luks.log'
time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
now = datetime.now().strftime('-%b-%d-%y-%H%M%S')

# Get Distribution
# Ubuntu and centos currently supported
try:
    with open('/etc/os-release', 'r') as f:
        os_file = f.read()
        regex = r'\sID="?(\w+)"?\n'
        ID = re.search(regex, os_file).group()
        DISTNAME = 'ubuntu' if ID == 'ubuntu' else 'centos'
except FileNotFoundError:
    print("Not running a distribution with /etc/os-release available")



################################################################################
# FUNCTIONS

#____________________________________
# Intro banner
def intro():
    NEW_PWD = ''
    while not (re.search(r'\w', NEW_PWD) and re.search(r'\d', NEW_PWD)):
        NEW_PWD = ''.join([random.choice(alphanum) for i in range(8)])
    
    print('=========================================================')
    print('                      ELIXIR-Italy')
    print('               Filesystem encryption script\n')             
    print('A password with at least 8 alphanumeric string is needed')
    print("There's no way to recover your password.")
    print('Example (automatic random generated passphrase):')
    print(f'                      {NEW_PWD}\n')
    print('You will be required to insert your password 3 times:')
    print('  1. Enter passphrase')
    print('  2. Verify passphrase')
    print('  3. Unlock your volume\n')
    print('=========================================================')


#____________________________________
# Log levels:
# DEBUG
# INFO
# WARNING
# ERROR

# Check if loglevel is valid
def check_loglevel(loglevel):
    valid_loglevels = ['INFO','DEBUG','WARNING','ERROR']
    if loglevel not in valid_loglevels:
        raise ValueError(f'loglevel must be one of {valid_loglevels}')


# Echo function
def echo(loglevel, text):
    check_loglevel(loglevel)
    message = f'{loglevel} {time} {text}\n'
    print(message)
    return message


# Logs config
logging.basicConfig(filename=LOGFILE, filemode='a+', level=0, format='%(levelname)s %(asctime)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S')


#________________________________
# Function to run bash commands
def run_command(cmd, log_stderr_stdout = False):
    """
    Run subprocess call redirecting stdout, stderr and the command exit code.
    """
    proc = subprocess.Popen(args=cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    communicateRes = proc.communicate()
    stdout, stderr = [x.decode('utf-8') for x in communicateRes]
    status = proc.wait()

    # Functionality to replicate cmd >> "$LOGFILE" 2>&1
    if log_stderr_stdout:
        with open(LOGFILE, 'a') as log:
            log.write(f'{stdout}\n{stderr}')

    return stdout, stderr, status


#____________________________________
# Lock/UnLock Section
def lock(LOCKFILE):

    # Start locking attempt
    try:
        lock = zc.lockfile.LockFile(LOCKFILE, content_template='{pid};{hostname}') # storing the PID and hostname in LOCKFILE
        return lock
    except zc.lockfile.LockError:
        # Lock failed: retrieve the PID of the locking process
        with open(LOCKFILE, 'r') as lock_file:
            pid_hostname = lock_file.readline()
            PID = re.search(r'^\s(\d+);', pid_hostname).group()
        echo('ERROR', f'Another script instance is active: PID {PID}')
        exit(2)

    # lock is valid and OTHERPID is active - exit, we're locked!
    echo('ERROR', f'Lock failed, PID {PID} is active')
    echo('ERROR', f'Another {STAT} process is active')
    echo('ERROR', f'If you are sure {STAT} is not already running,')
    echo('ERROR', f'You can remove {LOCKFILE} and restart {STAT}')
    exit(2)


#____________________________________
def unlock(lock, LOCKFILE, do_exit=True):
    lock.close()
    os.remove(LOCKFILE)
    if do_exit:
        exit()


#____________________________________
def unlock_if_false(function_return, lock, LOCKFILE):
    if function_return == False:
        unlock(lock, LOCKFILE)


#____________________________________
def create_random_cryptdev_name():
    return ''.join([random.choice(ascii_lowercase) for i in range(8)])


#____________________________________
def info(device, cipher_algorithm, hash_algorithm, keysize, cryptdev, mountpoint, filesystem):
    echo('DEBUG', f'LUKS header information for {device}')
    echo('DEBUG', f'Cipher algorithm: {cipher_algorithm}')
    echo('DEBUG', f'Hash algorithm {hash_algorithm}')
    echo('DEBUG', f'Keysize: {keysize}')
    echo('DEBUG', f'Device: {device}')
    echo('DEBUG', f'Crypt device: {cryptdev}')
    echo('DEBUG', f'Mapper: /dev/mapper/{cryptdev}')
    echo('DEBUG', f'Mountpoint: {mountpoint}')
    echo('DEBUG', f'File system: {filesystem}')


#____________________________________
# Install cryptsetup
def install_cryptsetup(log_stderr_stdout=False):
    if DISTNAME == 'ubuntu':
        echo('INFO', 'Distribution: Ubuntu. Using apt.')
        run_command('apt-get install -y cryptsetup pv', log_stderr_stdout)
    else:
        echo('INFO', 'Distribution: CentOS. Using yum.')
        run_command('yum install -y cryptsetup-luks pv', log_stderr_stdout)


#____________________________________
# Check cryptsetup installation
def check_cryptsetup():
    echo('INFO', 'Check if the required applications are installed...')
    
    _, _, dmsetup_status = run_command('type -P dmsetup &>/dev/null')
    if dmsetup_status != 0:
        echo('INFO', 'dmsetup is not installed. Installing...')
        if DISTNAME == 'ubuntu':
            run_command('apt-get install -y dmsetup')
        else:
            run_command('yum install -y device-mapper')
    
    _, _, cryptsetup_status = run_command('type -P cryptsetup &>/dev/null')
    if cryptsetup_status != 0:
        echo('INFO', 'cryptsetup is not installed. Installing...')
        install_cryptsetup(log_stderr_stdout=True)
        echo('INFO', 'cryptsetup installed.')


#____________________________________
# Passphrase Random generation
def create_random_secret(passphrase_length):
    return ''.join([random.choice(alphanum) for i in range(passphrase_length)])


#____________________________________
def end_encrypt_procedure(SUCCESS_FILE):
    # send signal to unclok waiting condition for automation software (e.g Ansible)
    with open(SUCCESS_FILE, 'w') as success_file:
        success_file.write('LUKS encryption completed.') # WARNING DO NOT MODFIFY THIS LINE, THIS IS A CONTROL STRING FOR ANSIBLE
    echo('INFO', 'SUCCESSFUL.')


#____________________________________
def end_volume_setup_procedure(SUCCESS_FILE):
    # send signal to unclok waiting condition for automation software (e.g Ansible)
    with open(SUCCESS_FILE,'w') as success_file:
        success_file.write('Volume setup completed.')
    echo('INFO', 'SUCCESSFUL.')


#____________________________________
def load_default_config(defaults_file='./defaults.conf'):
    global cipher_algorithm, keysize, hash_algorithm, device, cryptdev, mountpoint, filesystem, paranoid, non_interactive, foreground, luks_cryptdev_file, luks_header_backup

    if os.path.isfile(defaults_file):
        logging.info('Loading default configuration from defaults.conf')
        config = ConfigParser()
        config.read_file(open(defaults_file))
        defaults = config['defaults']
        cipher_algorithm = defaults['cipher_algorithm']
        keysize = defaults['keysize']
        hash_algorithm = defaults['hash_algorithm']
        device = defaults['device']
        cryptdev = defaults['cryptdev']
        mountpoint = defaults['mountpoint']
        filesystem = defaults['filesystem']
        paranoid = defaults['paranoid']
        non_interactive = defaults['non_interactive']
        foreground = defaults['foreground']
        luks_cryptdev_file = defaults['luks_cryptdev_file']
        luks_header_backup = defaults['luks_header_backup']


#____________________________________
# Read ini file
def read_ini_file(cryptdev_ini_file):
    config = ConfigParser()
    config.read_file(open(cryptdev_ini_file))
    luks_section = config['luks']
    return {key:luks_section[key] for key in luks_section}


#____________________________________
def unwrap_vault_token(url, wrapping_token):
    url = url + '/v1/sys/wrapping/unwrap'
    headers = { "X-Vault-Token": wrapping_token }

    response = requests.post(url, headers=headers, verify=False)
    response.raise_for_status()
    deserialized_response = json.loads(response.text)

    try:
        deserialized_response["auth"]["client_token"]
    except KeyError:
        raise Exception("[FATAL] Unable to unwrap vault token.")

    return deserialized_response["auth"]["client_token"]


#____________________________________
def post_secret(url, path, token, key, value):
    url = url + '/v1/secrets/data/' + path
    headers = { "X-Vault-Token": token }
    data = '{ "options": { "cas": 0 }, "data": { "'+key+'": "'+value+'"} }'

    response = requests.post(url, headers=headers, data=data, verify=False)
    response.raise_for_status()
    deserialized_response = json.loads(response.text)

    try:
        deserialized_response["data"]
    except KeyError:
        raise Exception("[FATAL] Unable to write vault path.")

    return deserialized_response


#____________________________________
def parse_response(response):
    if not response["data"]["created_time"]:
        raise Exception("No cretation time")

    if response["data"]["destroyed"] != False:
        raise Exception("Token already detroyed")

    if response["data"]["version"] != 1:
        raise Exception("Token not at 1st verion")

    if response["data"]["deletion_time"] != "":
        raise Exception("Token aready deleted")

    return 0


#______________________________________
def revoke_token(url, token):
    url = url + '/v1/auth/token/revoke-self'
    headers = { "X-Vault-Token": token }
    response = requests.post( url, headers=headers, verify=False )


#____________________________________
def write_secret_to_vault(vault_url, wrapping_token, secret_path, user_key, user_value):
    # Check vault
    r = requests.get(vault_url)
    r.raise_for_status()

    write_token = unwrap_vault_token(vault_url, wrapping_token)
    response_output = post_secret(vault_url, secret_path, write_token, user_key, user_value)
    parse_response(response_output)

    revoke_token(vault_url, write_token)


#____________________________________
# Used in setup_device
def check_passphrase(passphrase_length, passphrase, passphrase_confirmation):
    if passphrase_length == None:
        if passphrase == None:
            echo('ERROR', "Missing passphrase!")
            return False
        if passphrase_confirmation == None:
            echo('ERROR', 'Missing confirmation passphrase!')
            return False
        if passphrase == passphrase_confirmation:
            s3cret = passphrase
        else:
            echo('ERROR', 'No matching passphrases!')
            return False
    else:
            s3cret = create_random_secret(passphrase_length)
            return s3cret


#____________________________________
class device:
    
    def __init__(self, device_name, cryptdev, mountpoint, filesystem):
        self.device_name = device_name
        self.cryptdev = cryptdev
        self.mountpoint = mountpoint
        self.filesystem = filesystem
    
    def check_vol(self):
        logging.debug('Checking storage volume.')

        if os.path.ismount(self.mountpoint):
            mounted_device, _, _ = run_command(f'df -P {self.mountpoint} | tail -1 | cut -d" " -f 1')
            logging.debug(f'Device name: {mounted_device}')

        else:
            if Path(self.device_name).is_block_device():
                logging.debug(f'External volume on {self.device_name}. Using it for encryption.')
                if not os.path.isdir(self.mountpoint):
                    logging.debug(f'Creating {self.mountpoint}')
                    os.makedirs(self.mountpoint, exist_ok=True)
                    logging.debug(f'Device name: {self.device_name}')
                    logging.debug(f'Mountpoint: {self.mountpoint}')
            else:
                logging.error('Device not mounted, exiting! Please check logfile:')
                logging.error(f'No device mounted to {self.mountpoint}')
                run_command('df -h', log_stderr_stdout=True)
                return False # TODO: unlock and terminate process
    
    def is_encrypted(self):
        logging.debug('Checking if the volume is already encrypted.')
        devices, _, _ = run_command('lsblk -p -o NAME,FSTYPE')
        if re.search(f'{self.device_name}\s+crypto_LUKS', devices):
                logging.info('The volume is already encrypted')
                return True
        else:
            return False

    def umount_vol(self):
        logging.info('Umounting device.')
        run_command(f'umount {self.mountpoint}', log_stderr_stdout=True)
        logging.info(f'{self.device_name} umounted, ready for encryption!')

    def luksFormat(self, s3cret, cipher_algorithm, keysize, hash_algorithm):
        return run_command(f'printf "{s3cret}\n" | cryptsetup -v --cipher {cipher_algorithm} --key-size {keysize} --hash {hash_algorithm} --iter-time 2000 --use-urandom luksFormat {self.device_name} --batch-mode')

    def luksHeaderBackup(self, luks_header_backup_dir, luks_header_backup_file):
        return run_command(f'cryptsetup luksHeaderBackup --header-backup-file {luks_header_backup_dir}/{luks_header_backup_file} {self.device_name}')

    def luksOpen(self, s3cret):
        return run_command(f'printf "{s3cret}\n" | cryptsetup luksOpen {self.device_name} {self.cryptdev}')

    def setup_device(self, luks_header_backup_dir, luks_header_backup_file, cipher_algorithm, keysize, hash_algorithm,
                    # vault_url, wrapping_token, secret_path, user_key
                    passphrase_length, passphrase, passphrase_confirmation):
            echo('INFO', 'Start the encryption procedure.')
            logging.info(f'Using {cipher_algorithm} algorithm to luksformat the volume.')
            logging.debug('Start cryptsetup')
            info(self.device_name, cipher_algorithm, hash_algorithm, keysize, self.cryptdev, self.mountpoint, self.filesystem)
            logging.debug('Cryptsetup full command:')
            logging.debug('cryptsetup -v --cipher $cipher_algorithm --key-size $keysize --hash $hash_algorithm --iter-time 2000 --use-urandom --verify-passphrase luksFormat $device --batch-mode')

            s3cret = check_passphrase(passphrase_length, passphrase, passphrase_confirmation)
            if s3cret == False:
                return False # TODO: unlock and exit
            
            # Start encryption procedure
            self.luksFormat(s3cret, cipher_algorithm, keysize, hash_algorithm)

            # Write the secret to vault
            # write_secret_to_vault(vault_url, wrapping_token, secret_path, user_key, s3cret)

            # Backup LUKS header
            if not os.path.isdir(luks_header_backup_dir):
                os.mkdir(luks_header_backup_dir)
            _, _, luksHeaderBackup_ec = self.luksHeaderBackup(luks_header_backup_dir, luks_header_backup_file)

            if luksHeaderBackup_ec != 0:
                # Cryptsetup returns 0 on success and a non-zero value on error.
                # Error codes are:
                # 1 wrong parameters
                # 2 no permission (bad passphrase)
                # 3 out of memory
                # 4 wrong device specified
                # 5 device already exists or device is busy.
                logging.error(f'Command cryptsetup failed with exit code {luksHeaderBackup_ec}! Mounting {self.device_name} to {self.mountpoint} and exiting.')
                if luksHeaderBackup_ec == 2:
                    echo('ERROR', 'Bad passphrase. Please try again.')
                return False # TODO: unlock and exit

            return s3cret
    
    def open_device(self, s3cret):
        echo('INFO', 'Open LUKS volume')
        if not Path(f'/dev/mapper{self.cryptdev}').is_block_device():
            _, _, openec = self.luksOpen(s3cret)
            
            if openec != 0:
                if openec == 2:
                    echo('ERROR', 'Bad passphrase. Please try again.')
                    return False # TODO: unlock and exit
                else:
                    echo('ERROR', f'Crypt device already exists! Please check logs: {LOGFILE}')
                    logging.error('Unable to luksOpen device.')
                    logging.error(f'/dev/mapper/{self.cryptdev} already exists.')
                    logging.error(f'Mounting {self.device_name} to {self.mountpoint} again.')
                    run_command(f'mount {self.device_name} {self.mountpoint}', log_stderr_stdout=True)
                    return False # TODO: unlock and exit
    
    def encryption_status(self):
        logging.info(f'Check {self.cryptdev} status with cryptsetup status')
        run_command(f'cryptsetup -v status {self.cryptdev}', log_stderr_stdout=True)
    
    def create_cryptdev_ini_file(self, luks_cryptdev_file, cipher_algorithm, hash_algorithm, keysize, luks_header_backup_dir, luks_header_backup_file, now=now):
        luksUUID, _, _ = run_command(f'cryptsetup luksUUID {self.device_name}')

        with open(luks_cryptdev_file, 'w') as f:
            f.write('# This file has been generated using fast_luks.sh script\n')
            f.write('# https://github.com/mtangaro/galaxycloud-testing/blob/master/fast_luks.sh\n')
            f.write('# The device name could change after reboot, please use UUID instead.\n')
            f.write('# LUKS provides a UUID (Universally Unique Identifier) for each device.\n')
            f.write('# This, unlike the device name (eg: /dev/vdb), is guaranteed to remain constant\n')
            f.write('# as long as the LUKS header remains intact.\n')
            f.write(f'# LUKS header information for {self.device_name}\n')
            f.write(f'# luks-{now}\n')
            f.write(f'[luks]\n')
            f.write(f'cipher_algorithm = {cipher_algorithm}\n')
            f.write(f'hash_algorithm = {hash_algorithm}\n')
            f.write(f'keysize = {keysize}\n')
            f.write(f'device = {self.device_name}\n')
            f.write(f'uuid = {luksUUID}\n')
            f.write(f'cryptdev = {self.cryptdev}\n')
            f.write(f'mapper = /dev/mapper/{self.cryptdev}\n')
            f.write(f'mountpoint = {self.mountpoint}\n')
            f.write(f'filesystem = {self.filesystem}\n')
            f.write(f'header_path = {luks_header_backup_dir}/{luks_header_backup_file}\n')
        
        run_command(f'dmsetup info /dev/mapper/{self.cryptdev}', log_stderr_stdout=True)
        run_command(f'cryptsetup luksDump {self.device_name}', log_stderr_stdout=True)

    def wipe_data(self):
        echo('INFO', 'Paranoid mode selected. Wiping disk')
        logging.info('Wiping disk data by overwriting the entire drive with random data.')
        logging.info('This might take time depending on the size & your machine!')
        
        run_command(f'dd if=/dev/zero of=/dev/mapper/{self.cryptdev} bs=1M status=progress')
        
        logging.info(f'Block file /dev/mapper/{self.cryptdev} created.')
        logging.info('Wiping done.')

    def create_fs(self):
        echo('INFO', 'Creating filesystem.')
        logging.info(f'Creating {self.filesystem} filesystem on /dev/mapper/{self.cryptdev}')
        _, _, mkfs_ec = run_command(f'mkfs -t {self.filesystem} /dev/mapper/{self.cryptdev}', log_stderr_stdout=True)
        if mkfs_ec != 0:
            echo('ERROR', f'While creating {self.filesystem} filesystem. Please check logs.')
            echo('ERROR', 'Command mkfs failed!')
            return False #TODO: unlock and exit
    
    def mount_vol(self):
        echo('INFO', 'Mounting encrypted device.')
        logging.info(f'Mounting /dev/mapper/{self.cryptdev} to {self.mountpoint}')
        run_command(f'mount /dev/mapper/{self.cryptdev} {self.mountpoint}', log_stderr_stdout=True)
        run_command('df -Hv', log_stderr_stdout=True)

    def encrypt(self, cipher_algorithm, keysize, hash_algorithm, luks_header_backup_dir, luks_header_backup_file, 
               LOCKFILE, SUCCESS_FILE, luks_cryptdev_file, # vault_url, wrapping_token, secret_path, user_key,
               passphrase_length, passphrase, passphrase_confirmation):
        
        locked = lock(LOCKFILE) # Create lock file

        cryptdev = create_random_cryptdev_name() # Assign random name to cryptdev

        check_cryptsetup() # Check that cryptsetup and dmsetup are installed

        unlock_if_false(self.check_vol(), locked, LOCKFILE) # Check which virtual volume is mounted to mountpoint, unlock and exit if it's not mounted

        if not self.is_encrypted(): # Check if the volume is encrypted, if it's not start the encryption procedure
            self.umount_vol()
            s3cret = self.setup_device(luks_header_backup_dir, luks_header_backup_file, cipher_algorithm, keysize, hash_algorithm,
                                        # vault_url, wrapping_token, secret_path, user_key,
                                        passphrase_length, passphrase, passphrase_confirmation)
            unlock_if_false(s3cret, locked, LOCKFILE)

            with open('./s3cret_file','w') as sf: # TODO: !!!!!! REMOVE THIS AFTER TROUBLESHOOTING !!!!!!
                sf.write(s3cret)
        
        unlock_if_false(self.open_device(s3cret), locked, LOCKFILE) # Create mapping

        self.encryption_status() # Check status

        self.create_cryptdev_ini_file(luks_cryptdev_file, cipher_algorithm, hash_algorithm, keysize, luks_header_backup_dir, luks_header_backup_file) # Create ini file

        end_encrypt_procedure(SUCCESS_FILE) # LUKS encryption finished. Print end dialogue.

        unlock(locked, LOCKFILE, do_exit=False) # Unlock
    
    def volume_setup(self, cipher_algorithm, hash_algorithm, keysize, luksUUID, luks_header_backup_dir,
                     luks_header_backup_file, LOCKFILE, SUCCESS_FILE):
        
        locked = lock(LOCKFILE) # Create lock file

        unlock_if_false(self.create_fs(), locked, LOCKFILE) # Create filesystem

        self.mount_vol() # Mount volume

        self.create_cryptdev_ini_file(now, cipher_algorithm, hash_algorithm, keysize, luksUUID,
                                      luks_header_backup_dir, luks_header_backup_file) # Update ini file
        
        end_volume_setup_procedure(SUCCESS_FILE) # Volume setup finished. Print end dialogue

        unlock(locked, LOCKFILE, do_exit=False) # Unlock once done


def main_script(device_name='/dev/vdb', cryptdev='crypt', mountpoint='/export', filesystem='ext4',
                cipher_algorithm='aes-xts-plain64', keysize=256, hash_algorithm='sha256', luks_header_backup_dir='/etc/luks',
                luks_header_backup_file='luks-header.bck', luks_cryptdev_file='/etc/luks/luks-cryptdev.ini',
                passphrase_length=8, passphrase=None, passphrase_confirmation=None):
    
    device_to_encrypt = device(device_name, cryptdev, mountpoint, filesystem)
    
    LOCKFILE = '/var/run/fast-luks-encryption.lock'
    SUCCESS_FILE = '/var/run/fast-luks-encryption.success'
    
    device_to_encrypt.encrypt(cipher_algorithm, keysize, hash_algorithm, luks_header_backup_dir, luks_header_backup_file, 
                              LOCKFILE, SUCCESS_FILE, luks_cryptdev_file, passphrase_length, passphrase, passphrase_confirmation)
                              # vault_url, wrapping_token, secret_path, user_key

    variables = read_ini_file(luks_cryptdev_file)
    luksUUID = variables['uuid']
    LOCKFILE = '/var/run/fast-luks-volume-setup.lock'
    SUCCESS_FILE = '/var/run/fast-luks-volume-setup.success'

    device_to_encrypt.volume_setup(cipher_algorithm, hash_algorithm, keysize, luksUUID, luks_header_backup_dir,
                        luks_header_backup_file, LOCKFILE, SUCCESS_FILE)