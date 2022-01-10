# Import dependencies
from flask import Flask
import json
import os
import logging
from configparser import ConfigParser

# Import internal dependencies
from .luksctl_run import wn



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
    nfs_mountpoint_list = json.loads(api_config['NFS_MOUNTPOINT_LIST']) if 'NFS_MOUNTPOINT_LIST' in api_config else None
    
    # Define node instance
    wn_node = wn(nfs_mountpoint_list)

else:
    raise FileNotFoundError('Cryptdev ini file missing.')


@app.route('/luksctl_api_wn/v1.0/status', methods=['GET'])
def get_status():
    return wn_node.get_status()


@app.route('/luksctl_api_wn/v1.0/nfs-mount', methods=['POST'])
def nfs_mount():
    return wn_node.nfs_mount()
