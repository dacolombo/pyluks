# Import dependencies
from flask import Flask, request, abort
import json
import os
import logging
from configparser import ConfigParser

# Import internal dependencies
from .luksctl_run import master, api_logger



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
    infrastructure_config = api_config['INFRASTRUCTURE_CONFIGURATION'] if 'INFRASTRUCTURE_CONFIGURATION' in api_config else None
    virtualization_type = api_config['VIRTUALIZATION_TYPE'] if 'VIRTUALIZATION_TYPE' in api_config else None
    node_list = json.loads(api_config['WN_IPS']) if 'WN_IPS' in api_config else None
    
    # Define node instance
    master_node = master(infrastructure_config, virtualization_type, node_list)

else:
    raise FileNotFoundError('Cryptdev ini file missing.')




################################################################################
# FUNCTIONS

#______________________________________
@app.route('/luksctl_api/v1.0/status', methods=['GET'])
def get_status():
    
    return master_node.get_status()


#______________________________________
@app.route('/luksctl_api/v1.0/open', methods=['POST'])
def luksopen():

    if not request.json or \
       not 'vault_url' in request.json or \
       not 'vault_token' in request.json or \
       not 'secret_root' in request.json or \
       not 'secret_path' in request.json or \
       not 'secret_key' in request.json:
       abort(400)

    wn_list = master_node.get_node_list() 
    if wn_list != None:
        api_logger.debug(wn_list)

    return master_node.open(vault_url=request.json['vault_url'],
                            wrapping_token=request.json['vault_token'],
                            secret_root=request.json['secret_root'],
                            secret_path=request.json['secret_path'],
                            secret_key=request.json['secret_key'])
