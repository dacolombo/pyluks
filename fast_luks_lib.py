#! /usr/bin/env python3


# import dependencies
import random
from string import ascii_letters, digits, ascii_lowercase
import subprocess
import os
from pathlib import Path
from datetime import datetime
import re
import zc.lockfile
from configparser import ConfigParser


################################################################################
# VARIABLES
alphanum = ascii_letters + digits
LOGFILE = '/tmp/fast_luks.log'
now = datetime.now().strftime('-%b-%d-%y-%H%M%S')


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
time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

# Echo functions
def echo_info(info):
    info = f'INFO {time} {info}\n'
    print(info)
    return info

def echo_debug(debug):
    debug = f'DEBUG {time} {debug}\n'
    print(debug)
    return debug

def echo_warn(warn):
    warn = f'WARNING {time} {warn}\n'
    print(warn)
    return warn

def echo_error(error):
    error = f'ERROR {time} {error}\n'
    print(error)
    return error


# Logs functions
def logs_info(info):
    with open(LOGFILE, 'a') as log:
        log.write(echo_info(info))

def logs_debug(debug):
    with open(LOGFILE, 'a') as log:
        log.write(echo_debug(debug))

def logs_warn(warn):
    with open(LOGFILE, 'a') as log:
        log.write(echo_warn(warn))

def logs_error(error):
    with open(LOGFILE, 'a') as log:
        log.write(echo_error(error))


#________________________________
# Get Distribution
# Ubuntu and centos currently supported

try:
    with open('/etc/os-release', 'r') as f:
        os_file = f.read()
        regex = r'\sID="(\w+)"'
        ID = re.findall(regex, os_file)[0]
        DISTNAME = 'ubuntu' if ID == 'ubuntu' else 'centos'
except FileNotFoundError:
    print("Not running a distribution with /etc/os-release available")


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
        echo_error(f'Another script instance is active: PID {PID}')
        exit(2)

    # if lock is stale, remove it and restart
    # this is probably not needed: if the process is closed (it does not respond to kill -0) and the 
    # file is still present, it's not locked so it can be locked by the function.
    #try:
    #    os.kill(PID, 0)
    #except OSError:
    #    # lock is stale, remove it and restart
    #    echo_debug(f'Removing fake lock file of nonexistant PID {PID}')
    #    os.remove(LOCKFILE)
    #    echo_debug('Restarting luks script')
    #   TODO: re-run script

    # lock is valid and OTHERPID is active - exit, we're locked!
    echo_error(f'Lock failed, PID {PID} is active')
    echo_error(f'Another {STAT} process is active')
    echo_error(f'If you are sure {STAT} is not already running,')
    echo_error(f'You can remove {LOCKFILE} and restart {STAT}')
    exit(2)


#____________________________________
def unlock(lock, LOCKFILE):
    lock.close()
    os.remove(LOCKFILE)


#____________________________________
def create_random_cryptdev_name():
    return ''.join([random.choice(ascii_lowercase) for i in range(8)])


#____________________________________
def info(device, cipher_algorithm, hash_algorithm, keysize, cryptdev, mountpoint, filesystem):
    echo_debug(f'LUKS header information for {device}')
    echo_debug(f'Cipher algorithm: {cipher_algorithm}')
    echo_debug(f'Hash algorithm {hash_algorithm}')
    echo_debug(f'Keysize: {keysize}')
    echo_debug(f'Device: {device}')
    echo_debug(f'Crypt device: {cryptdev}')
    echo_debug(f'Mapper: /dev/mapper/{cryptdev}')
    echo_debug(f'Mountpoint: {mountpoint}')
    echo_debug(f'File system: {filesystem}')


#____________________________________
# Install cryptsetup
def install_cryptsetup(log_stderr_stdout=False):
    if DISTNAME == 'ubuntu':
        echo_info('Distribution: Ubuntu. Using apt.')
        run_command('apt-get install -y cryptsetup pv', log_stderr_stdout)
    else:
        echo_info('Distribution: CentOS. Using yum.')
        run_command('yum install -y cryptsetup-luks pv', log_stderr_stdout)


#____________________________________
# Check cryptsetup installation
def check_cryptsetup():
    echo_info('Check if the required applications are installed...')
    
    _, _, dmsetup_status = run_command('type -P dmsetup &>/dev/null')
    if dmsetup_status != 0:
        echo_info('dmsetup is not installed. Installing...') # TODO: add install device_mapper
    
    _, _, cryptsetup_status = run_command('type -P cryptsetup &>/dev/null')
    if cryptsetup_status != 0:
        echo_info('cryptsetup is not installed. Installing...')
        install_cryptsetup(log_stderr_stdout=True)
        echo_info('cryptsetup installed.')


#____________________________________
# Check volume 
def check_vol(mountpoint, device):
    logs_debug('Checking storage volume.')

    #num_mountpoint, _, _ = run_command(f'mount | grep -c {mountpoint}')
    if os.path.ismount(mountpoint):
        device, _, _ = run_command(f'df -P {mountpoint} | tail -1 | cut -d" " -f 1')
        logs_debug(f'Device name: {device}')

    else:
        if Path.is_block_device(Path(device)):
            logs_debug(f'External volume on {device}. Using it for encryption.')
            if not os.path.isdir(mountpoint):
                logs_debug(f'Creating {mountpoint}')
                os.makedirs(mountpoint, exist_ok=True)
                logs_debug(f'Device name: {device}')
                logs_debug(f'Mountpoint: {mountpoint}')
        else:
            logs_error('Device not mounted, exiting!')
            logs_error('Please check logfile:')
            logs_error(f'No device mounted to {mountpoint}')
            run_command('df -h', log_stderr_stdout=True)
            unlock(lock, LOCKFILE)
            exit(1)

#____________________________________
# Check if the volume is already encrypted.
# If yes, skip the encryption
def lsblk_check(device):
    logs_debug('Checking if the volume is already encrypted.')
    devices, _, _ = run_command('lsblk -p -o NAME,FSTYPE')
    if re.search(f'{device}\s+crypto_LUKS', devices):
            logs_info('The volume is already encrypted')
            return True
    else:
        return False


#____________________________________
# Umount volume
def umount_vol(mountpoint, device):
    logs_info('Umounting device.')
    run_command(f'umount {mountpoint}', log_stderr_stdout=True)
    logs_info(f'{device} umounted, ready for encryption!')


#____________________________________
# Passphrase Random generation
def create_random_secret(passphrase_length):
    return ''.join([random.choice(alphanum) for i in range(passphrase_length)])


#____________________________________
def setup_device(device, cryptdev, mountpoint, filesystem, #vault_url, wrapping_token, secret_path, user_key,
                 luks_header_backup_dir, luks_header_backup_file, lock, LOCKFILE, cipher_algorithm='aes-xts-plain64', keysize=256,
                 hash_algorithm='sha256', passphrase_length=None, passphrase=None, passphrase_confirmation=None):
    echo_info('Start the encryption procedure.')
    logs_info(f'Using {cipher_algorithm} algorithm to luksformat the volume.')
    logs_debug('Start cryptsetup')
    info(device, cipher_algorithm, hash_algorithm, keysize, cryptdev, mountpoint, filesystem)
    logs_debug('Cryptsetup full command:')
    logs_debug('cryptsetup -v --cipher $cipher_algorithm --key-size $keysize --hash $hash_algorithm --iter-time 2000 --use-urandom --verify-passphrase luksFormat $device --batch-mode')

    if passphrase_length == None:
        if passphrase == None:
            echo_error("Missing passphrase!")
            unlock(lock, LOCKFILE)
            exit(1)
        if passphrase_confirmation == None:
            echo_error('Missing confirmation passphrase!')
            unlock(lock, LOCKFILE)
            exit(1)
        if passphrase == passphrase_confirmation:
            s3cret = passphrase
        else:
            echo_error('No matching passphrases!')
            unlock(lock, LOCKFILE)
            exit(1)
    else:
        s3cret = create_random_secret(passphrase_length)
    
    # TODO the password can't be longer 512 char
    # Start encryption procedure
    cryptsetup_cmd = f'printf "{s3cret}\n" | cryptsetup -v --cipher {cipher_algorithm} --key-size {keysize} --hash {hash_algorithm} --iter-time 2000 --use-urandom luksFormat {device} --batch-mode'
    run_command(cryptsetup_cmd)

    #create_vault_env()
    #write_secret_to_vault_command = f'python3 ./write_secret_to_vault.py -v {vault_url} -w {wrapping_token} -s {secret_path} --key {user_key} --value {s3cret}'
    #write_secret_to_vault_proc = run_command(write_secret_to_vault_command)
    #delete_vault_env()

    # Backup LUKS header
    os.mkdir(luks_header_backup_dir)
    _, _, luksHeaderBackup_ec = run_command(f'cryptsetup luksHeaderBackup --header-backup-file {luks_header_backup_dir}/{luks_header_backup_file} {device}')

    if luksHeaderBackup_ec != 0:
        # Cryptsetup returns 0 on success and a non-zero value on error.
        # Error codes are:
        # 1 wrong parameters
        # 2 no permission (bad passphrase)
        # 3 out of memory
        # 4 wrong device specified
        # 5 device already exists or device is busy.
        logs_error(f'Command cryptsetup failed with exit code {luksHeaderBackup_ec}! Mounting {device} to {mountpoint} and exiting.')
        if luksHeaderBackup_ec == 2:
             echo_error('Bad passphrase. Please try again.')
        unlock(lock, LOCKFILE)
        exit(luksHeaderBackup_ec)

#____________________________________
def open_device(cryptdev, s3cret, device, mountpoint):
    echo_info('Open LUKS volume')
    if not Path(f'/dev/mapper/{cryptdev}').is_block_device():
        _, _, openec = run_command(f'printf "{s3cret}\n" | cryptsetup luksOpen {device} {cryptdev}')
        if openec != 0:
            if openec == 2:
                echo_error('Bad passphrase. Please try again.')
                unlock(lock, LOCKFILE)
                exit(openec)
            else:
                echo_error(f'Crypt device already exists! Please check logs: {LOGFILE}')
                logs_error('Unable to luksOpen device.')
                logs_error(f'/dev/mapper/{cryptdev} already exists.')
                logs_error(f'Mounting {device} to {mountpoint} again.')
                run_command(f'mount {device} {mountpoint}', log_stderr_stdout=True)
                unlock(lock, LOCKFILE)
                exit(1)


#____________________________________
def encryption_status(cryptdev):
    logs_info(f'Check {cryptdev} status with cryptsetup status')
    run_command(f'cryptsetup -v status {cryptdev}', log_stderr_stdout=True)


#____________________________________
# Create block file
# https://wiki.archlinux.org/index.php/Dm-crypt/Device_encryption
# https://wiki.archlinux.org/index.php/Dm-crypt/Drive_preparation
# https://wiki.archlinux.org/index.php/Disk_encryption#Preparing_the_disk
#
# Before encrypting a drive, it is recommended to perform a secure erase of the disk by overwriting the entire drive with random data.
# To prevent cryptographic attacks or unwanted file recovery, this data is ideally indistinguishable from data later written by dm-crypt.
def wipe_data():
    echo_info('Paranoid mode selected. Wiping disk')
    logs_info('Wiping disk data by overwriting the entire drive with random data.')
    logs_info('This might take time depending on the size & your machine!')
    
    run_command(f'dd if=/dev/zero of=/dev/mapper/{cryptdev} bs=1M status=progress')
    
    logs_info(f'Block file /dev/mapper/{cryptdev} created.')
    logs_info('Wiping done.')


#____________________________________
def create_fs(filesystem, cryptdev):
    echo_info('Creating filesystem.')
    logs_info(f'Creating {filesystem} filesystem on /dev/mapper/{cryptdev}')
    _, _, mkfs_ec = run_command(f'mkfs -t {filesystem} /dev/mapper/{cryptdev}', log_stderr_stdout=True)
    if mkfs_ec != 0:
        echo_error(f'While creating {filesystem} filesystem. Please check logs: {LOGFILE}')
        echo_error('Command mkfs failed!')
        unlock(lock, LOCKFILE)
        exit(1)


#____________________________________
def mount_vol(cryptdev, mountpoint):
    echo_info('Mounting encrypted device.')
    logs_info(f'Mounting /dev/mapper/{cryptdev} to {mountpoint}')
    run_command(f'mount /dev/mapper/{cryptdev} {mountpoint}', log_stderr_stdout=True)
    run_command('df -Hv', log_stderr_stdout=True)


#____________________________________
def create_cryptdev_ini_file(luks_cryptdev_file, device, cipher_algorithm, hash_algorithm, keysize, cryptdev, mountpoint,
                             filesystem, luks_header_backup_dir, luks_header_backup_file):
    if not os.path.isfile(luks_cryptdev_file):
        logs_debug(f'Create {luks_cryptdev_file}')
        run_command(f'install -D /dev/null {luks_cryptdev_file}')
    
    luksUUID, _, _ = run_command(f'cryptsetup luksUUID {device}')

    with open(luks_cryptdev_file, 'w') as luks_cryptdev_file:
        luks_cryptdev_file.write(f"""# This file has been generated using fast_luks.sh script
# https://github.com/mtangaro/galaxycloud-testing/blob/master/fast_luks.sh
# The device name could change after reboot, please use UUID instead.
# LUKS provides a UUID (Universally Unique Identifier) for each device.
# This, unlike the device name (eg: /dev/vdb), is guaranteed to remain constant
# as long as the LUKS header remains intact.
# LUKS header information for {device}
# luks-{now}
[luks]
cipher_algorithm = {cipher_algorithm}
hash_algorithm = {hash_algorithm}
keysize = {keysize}
device = {device}
uuid = {luksUUID}
cryptdev = {cryptdev}
mapper = /dev/mapper/{cryptdev}
mountpoint = {mountpoint}
filesystem = {filesystem}
header_path = {luks_header_backup_dir}/{luks_header_backup_file}
""")
    
    run_command(f'dmsetup info /dev/mapper/{cryptdev}', log_stderr_stdout=True)
    run_command(f'cryptsetup luksDump {device}', log_stderr_stdout=True)


#____________________________________
def end_encrypt_procedure(SUCCESS_FILE):
    # send signal to unclok waiting condition for automation software (e.g Ansible)
    with open(SUCCESS_FILE, 'w') as success_file:
        success_file.write('LUKS encryption completed.') # WARNING DO NOT MODFIFY THIS LINE, THIS IS A CONTROL STRING FOR ANSIBLE
    echo_info('SUCCESSFUL.')


#____________________________________
def end_volume_setup_procedure(SUCCESS_FILE):
    # send signal to unclok waiting condition for automation software (e.g Ansible)
    with open(SUCCESS_FILE,'w') as success_file:
        success_file.write('Volume setup completed.')
    echo_info('SUCCESSFUL.')


#____________________________________
def load_default_config():
    if os.path.isfile('./defaults.conf'):
        logs_info('Loading default configuration from defaults.conf')
        import defaults.conf
    else:
        logs_info('No defaults.conf file found. Loading built-in variables.')
        global cipher_algorithm, keysize, hash_algorithm, device, cryptdev, mountpoint, filesystem, paranoid, non_interactive, foreground, luks_cryptdev_file, luks_header_backup
        cipher_algorithm='aes-xts-plain64'
        keysize=256
        hash_algorithm='sha256'
        device='/dev/vdb'
        cryptdev='crypt'
        mountpoint='/export'
        filesystem='ext4'
        paranoid=False
        non_interactive=False
        foreground=False
        luks_cryptdev_file='/tmp/luks-cryptdev.ini'
        luks_header_backup='/tmp/luks-header.bck'


#____________________________________
# Read ini file
def read_ini_file(cryptdev_ini_file):
    config = ConfigParser()
    config.read_file(open(cryptdev_ini_file))
    luks_section = config['luks']
    return {key:luks_section[key] for key in luks_section}


#____________________________________
# TODO: def create_vault_env()


#____________________________________
# TODO: def delete_vault_env()

