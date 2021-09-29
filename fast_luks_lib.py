#! /usr/bin/env python3


# import dependencies
import random
from string import ascii_letters, digits, ascii_lowercase
import subprocess
import os
from pathlib import Path
import shutil
from datetime import datetime
import re
import zc.lockfile
from configparser import ConfigParser
import venv


################################################################################
# VARIABLES
alphanum = ascii_letters + digits
LOGFILE = '/tmp/fast_luks.log'
time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
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


# Logs function
def logs(loglevel, text):
    check_loglevel(loglevel)
    with open(LOGFILE, 'a+') as log:
        log.write(echo(loglevel, text))


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
        echo('ERROR', f'Another script instance is active: PID {PID}')
        exit(2)

    # if lock is stale, remove it and restart
    # this is probably not needed: if the process is closed (it does not respond to kill -0) and the 
    # file is still present, it's not locked so it can be locked by the function.
    #try:
    #    os.kill(PID, 0)
    #except OSError:
    #    # lock is stale, remove it and restart
    #    echo('DEBUG',f'Removing fake lock file of nonexistant PID {PID}')
    #    os.remove(LOCKFILE)
    #    echo('DEBUG','Restarting luks script')
    #   TODO: re-run script

    # lock is valid and OTHERPID is active - exit, we're locked!
    echo('ERROR', f'Lock failed, PID {PID} is active')
    echo('ERROR', f'Another {STAT} process is active')
    echo('ERROR', f'If you are sure {STAT} is not already running,')
    echo('ERROR', f'You can remove {LOCKFILE} and restart {STAT}')
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
        echo('INFO', 'dmsetup is not installed. Installing...') # TODO: add install device_mapper
    
    _, _, cryptsetup_status = run_command('type -P cryptsetup &>/dev/null')
    if cryptsetup_status != 0:
        echo('INFO', 'cryptsetup is not installed. Installing...')
        install_cryptsetup(log_stderr_stdout=True)
        echo('INFO', 'cryptsetup installed.')


#____________________________________
# Check volume 
def check_vol(mountpoint, device):
    logs('DEBUG', 'Checking storage volume.')

    #num_mountpoint, _, _ = run_command(f'mount | grep -c {mountpoint}')
    if os.path.ismount(mountpoint):
        device, _, _ = run_command(f'df -P {mountpoint} | tail -1 | cut -d" " -f 1')
        logs('DEBUG', f'Device name: {device}')

    else:
        if Path.is_block_device(Path(device)):
            logs('DEBUG', f'External volume on {device}. Using it for encryption.')
            if not os.path.isdir(mountpoint):
                logs('DEBUG', f'Creating {mountpoint}')
                os.makedirs(mountpoint, exist_ok=True)
                logs('DEBUG', f'Device name: {device}')
                logs('DEBUG', f'Mountpoint: {mountpoint}')
        else:
            logs('ERROR', 'Device not mounted, exiting!')
            logs('ERROR', 'Please check logfile:')
            logs('ERROR', f'No device mounted to {mountpoint}')
            run_command('df -h', log_stderr_stdout=True)
            unlock(lock, LOCKFILE)
            exit(1)

#____________________________________
# Check if the volume is already encrypted.
# If yes, skip the encryption
def lsblk_check(device):
    logs('DEBUG', 'Checking if the volume is already encrypted.')
    devices, _, _ = run_command('lsblk -p -o NAME,FSTYPE')
    if re.search(f'{device}\s+crypto_LUKS', devices):
            logs('INFO', 'The volume is already encrypted')
            return True
    else:
        return False


#____________________________________
# Umount volume
def umount_vol(mountpoint, device):
    logs('INFO', 'Umounting device.')
    run_command(f'umount {mountpoint}', log_stderr_stdout=True)
    logs('INFO', f'{device} umounted, ready for encryption!')


#____________________________________
# Passphrase Random generation
def create_random_secret(passphrase_length):
    return ''.join([random.choice(alphanum) for i in range(passphrase_length)])


#____________________________________
def setup_device(device, cryptdev, mountpoint, filesystem, #vault_url, wrapping_token, secret_path, user_key,
                 luks_header_backup_dir, luks_header_backup_file, lock, LOCKFILE, cipher_algorithm='aes-xts-plain64', keysize=256,
                 hash_algorithm='sha256', passphrase_length=None, passphrase=None, passphrase_confirmation=None):
    echo('INFO', 'Start the encryption procedure.')
    logs('INFO', f'Using {cipher_algorithm} algorithm to luksformat the volume.')
    logs('DEBUG', 'Start cryptsetup')
    info(device, cipher_algorithm, hash_algorithm, keysize, cryptdev, mountpoint, filesystem)
    logs('DEBUG', 'Cryptsetup full command:')
    logs('DEBUG', 'cryptsetup -v --cipher $cipher_algorithm --key-size $keysize --hash $hash_algorithm --iter-time 2000 --use-urandom --verify-passphrase luksFormat $device --batch-mode')

    if passphrase_length == None:
        if passphrase == None:
            echo('ERROR', "Missing passphrase!")
            unlock(lock, LOCKFILE)
            exit(1)
        if passphrase_confirmation == None:
            echo('ERROR', 'Missing confirmation passphrase!')
            unlock(lock, LOCKFILE)
            exit(1)
        if passphrase == passphrase_confirmation:
            s3cret = passphrase
        else:
            echo('ERROR', 'No matching passphrases!')
            unlock(lock, LOCKFILE)
            exit(1)
    else:
        s3cret = create_random_secret(passphrase_length)
    
    # TODO the password can't be longer 512 char
    # Start encryption procedure
    cryptsetup_cmd = f'printf "{s3cret}\n" | cryptsetup -v --cipher {cipher_algorithm} --key-size {keysize} --hash {hash_algorithm} --iter-time 2000 --use-urandom luksFormat {device} --batch-mode'
    run_command(cryptsetup_cmd)

    # Create vault venv and write the secret to vault under it
    venv_dir = create_vault_env()
    write_secret_to_vault_command = f'{venv_dir}/bin/python3 ./write_secret_to_vault.py -v {vault_url} -w {wrapping_token} -s {secret_path} --key {user_key} --value {s3cret}'
    run_command(write_secret_to_vault_command)
    delete_vault_env()

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
        logs('ERROR', f'Command cryptsetup failed with exit code {luksHeaderBackup_ec}! Mounting {device} to {mountpoint} and exiting.')
        if luksHeaderBackup_ec == 2:
             echo('ERROR', 'Bad passphrase. Please try again.')
        unlock(lock, LOCKFILE)
        exit(luksHeaderBackup_ec)

#____________________________________
def open_device(cryptdev, s3cret, device, mountpoint):
    echo('INFO', 'Open LUKS volume')
    if not Path(f'/dev/mapper/{cryptdev}').is_block_device():
        _, _, openec = run_command(f'printf "{s3cret}\n" | cryptsetup luksOpen {device} {cryptdev}')
        if openec != 0:
            if openec == 2:
                echo('ERROR', 'Bad passphrase. Please try again.')
                unlock(lock, LOCKFILE)
                exit(openec)
            else:
                echo('ERROR', f'Crypt device already exists! Please check logs: {LOGFILE}')
                logs('ERROR', 'Unable to luksOpen device.')
                logs('ERROR', f'/dev/mapper/{cryptdev} already exists.')
                logs('ERROR', f'Mounting {device} to {mountpoint} again.')
                run_command(f'mount {device} {mountpoint}', log_stderr_stdout=True)
                unlock(lock, LOCKFILE)
                exit(1)


#____________________________________
def encryption_status(cryptdev):
    logs('INFO', f'Check {cryptdev} status with cryptsetup status')
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
    echo('INFO', 'Paranoid mode selected. Wiping disk')
    logs('INFO', 'Wiping disk data by overwriting the entire drive with random data.')
    logs('INFO', 'This might take time depending on the size & your machine!')
    
    run_command(f'dd if=/dev/zero of=/dev/mapper/{cryptdev} bs=1M status=progress')
    
    logs('INFO', f'Block file /dev/mapper/{cryptdev} created.')
    logs('INFO', 'Wiping done.')


#____________________________________
def create_fs(filesystem, cryptdev):
    echo('INFO', 'Creating filesystem.')
    logs('INFO', f'Creating {filesystem} filesystem on /dev/mapper/{cryptdev}')
    _, _, mkfs_ec = run_command(f'mkfs -t {filesystem} /dev/mapper/{cryptdev}', log_stderr_stdout=True)
    if mkfs_ec != 0:
        echo('ERROR', f'While creating {filesystem} filesystem. Please check logs: {LOGFILE}')
        echo('ERROR', 'Command mkfs failed!')
        unlock(lock, LOCKFILE)
        exit(1)


#____________________________________
def mount_vol(cryptdev, mountpoint):
    echo('INFO', 'Mounting encrypted device.')
    logs('INFO', f'Mounting /dev/mapper/{cryptdev} to {mountpoint}')
    run_command(f'mount /dev/mapper/{cryptdev} {mountpoint}', log_stderr_stdout=True)
    run_command('df -Hv', log_stderr_stdout=True)


#____________________________________
def create_cryptdev_ini_file(luks_cryptdev_file, device, cipher_algorithm, hash_algorithm, keysize, cryptdev, mountpoint,
                             filesystem, luks_header_backup_dir, luks_header_backup_file):
    if not os.path.isfile(luks_cryptdev_file):
        logs('DEBUG', f'Create {luks_cryptdev_file}')
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
    echo('INFO', 'SUCCESSFUL.')


#____________________________________
def end_volume_setup_procedure(SUCCESS_FILE):
    # send signal to unclok waiting condition for automation software (e.g Ansible)
    with open(SUCCESS_FILE,'w') as success_file:
        success_file.write('Volume setup completed.')
    echo('INFO', 'SUCCESSFUL.')


#____________________________________
def load_default_config():
    if os.path.isfile('./defaults.conf'):
        logs('INFO', 'Loading default configuration from defaults.conf')
        import defaults.conf
    else:
        logs('INFO', 'No defaults.conf file found. Loading built-in variables.')
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
def create_vault_env(venv_dir='/tmp/vault_venv'):
    # Run vault python script in a specific virtual environment
    echo('INFO', 'Write LUKS passphrase to Hashicorp Vault')
    
    logs('DEBUG', 'Remove ansible virtualenv if exists')
    shutil.rmtree(venv_dir, ignore_errors=True)

    logs('DEBUG', 'Create virtualenv')
    venv.create(venv_dir, with_pip=True)
    return venv_dir


#____________________________________
def delete_vault_env(venv='/tmp/vault_venv'):
    echo('INFO', 'Delete Vault virtual environment')    
    shutil.rmtree(venv)

