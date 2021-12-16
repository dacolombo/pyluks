# Import dependencies
from flask import Flask, jsonify, request
import os
import logging
from configparser import ConfigParser

# Import internal dependencies
from fastluks import run_command
from .luksctl_run import wn


# Create logging facility
logging.basicConfig(filename='/tmp/luksctl-api.log', format='%(levelname)s %(asctime)s %(message)s', level='DEBUG')



################################################################################
# APP CONFIGS

app = Flask(__name__)

# Load configs
luks_cryptdev_file = '/etc/luks/luks-cryptdev.ini'
if os.path.exists(luks_cryptdev_file):
    
    # Read cryptdev ini file
    config = ConfigParser()
    config.read(luks_cryptdev_file)
    api_config = config['luksctl_api']

    # Set variables from cryptdev ini file
    nfs_mountpoint_list = api_config['NFS_MOUNTPOINT_LIST'] if 'NFS_MOUNTPOINT_LIST' in api_config else None
    
    # Define node instance
    wn_node = wn(nfs_mountpoint_list)

else:
    raise FileNotFoundError('Cryptdev ini file missing.')


@app.route('/luksctl_api_wn/v1.0/status', method=['GET'])
def get_status():
    return wn_node.get_status()


@app.route('/luksctl_api_wn/v1.0/nfs-mount', methods=['POST'])
def nfs_mount():
    return wn.nfs_mount()