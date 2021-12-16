# Import dependencies
from flask import jsonify
import json, requests
import os, sys, distro
from configparser import ConfigParser
import logging

# Import internal dependencies
from fastluks import run_command
from .vault_support import read_secret

# Create logging facility
logging.basicConfig(filename='/tmp/luksctl-api.log', format='%(levelname)s %(asctime)s %(message)s', level='DEBUG')



################################################################################
# NODES CLASSES

class master:


    def __init__(self, infra_config, virtualization_type=None, node_list=None):

        self.infra_config = infra_config
        self.virtualization_type = virtualization_type
        self.node_list = node_list
        self.distro_id = distro.id()


    def get_infra_config(self):
        return self.infra_config

    def get_virtualization_type(self):
        return self.virtualization_type

    def get_node_list(self):
        return self.node_list


    def write_api_config(self, luks_cryptdev_file='/etc/luks/luks-cryptdev.ini'):

        config = ConfigParser()

        config.add_section('luksctl_api')
        api_config = config['luksctl_api']

        api_config['INFRASTRUCTURE_CONFIGURATION'] = self.infra_config
        
        if self.virtualization_type != None:
            api_config['VIRTUALIZATION_TYPE'] = self.virtualization_type

        if self.node_list != None:
            api_config['WN_IPS'] = self.node_list

        with open(luks_cryptdev_file, 'a+') as f:
            config.write(f)


    def write_systemd_unit_file(self, service_file='/etc/systemd/system/luksctl-api.service', ssl=False):
        
        # Exit if command is not run as root
        if not os.geteuid() == 0:
            sys.exit('Error: write_systemd_unit_file must be run as root.')
        
        config = ConfigParser()
        config.optionxform = str
        
        config.add_section('Unit')
        config['Unit']['Description'] = 'Gunicorn instance to serve luksctl api server'
        config['Unit']['After'] = 'network.target'

        config.add_section('Service')
        config['Service']['User'] = 'luksctl_api'
        config['Service']['Group'] = 'luksctl_api'
        config['Service']['Working_directory'] = '/home/luksctl_api/luksctl_api'
        config['Service']['Environment'] = '"PATH=/home/luksctl_api/luksctl_api/venv/bin"'
        if ssl:
            config['Service']['ExecStart'] = '/home/luksctl_api/luksctl_api/venv/bin/gunicorn --workers 2 --bind 0.0.0.0:5000 -m 007 --certfile=/etc/luks/cert.pem --keyfile=/etc/luks/key.pem app:master_app'
        else:
            config['Service']['ExecStart'] = '/home/luksctl_api/luksctl_api/venv/bin/gunicorn --workers 2 --bind 0.0.0.0:5000 -m 007 app:master_app'
        
        config.add_section('Install')
        config['Install']['WantedBy'] = 'multi-user.target'

        with open(service_file, 'w') as sf:
            config.write(sf)


    def get_status(self):

        status_command = 'sudo luksctl status'
        status, stdout, stderr = run_command(status_command)

        logging.debug(f'Volume status stdout: {stdout}')
        logging.debug(f'Volume status stderr: {stderr}')
        logging.debug(f'Volume status: {status}')

        if str(status) == '0':
            return jsonify({'volume_state': 'mounted' })
        elif str(status)  == '1':
            return jsonify({'volume_state': 'unmounted' })
        else:
            return jsonify({'volume_state': 'unavailable', 'output': stdout, 'stderr': stderr })


    def open(self, vault_url, wrapping_token, path, secret_key, secret_root):

        status_command = 'sudo luksctl status'
        status, stodut, stderr = exec_cmd(status_command)

        if str(status) == '0':
            return jsonify({'volume_state': 'mounted'})
        
        else:
            # Read passphrase from vault
            secret = read_secret(vault_url, wrapping_token, path, secret_key, secret_root)
            
            # Open volume
            open_command = f'printf "{secret}\n" | sudo luksctl open' 
            status, stdout, stderr = exec_cmd(command)

            logging.debug(f'Volume status stdout: {stdout}')
            logging.debug(f'Volume status stderr: {stderr}')
            logging.debug(f'Volume status: {status}')

            if str(status) == '0':
                if self.infra_config == 'cluster':
                    self.nfs_restart()
                elif self.virtualization_type == 'docker':
                    self.docker_restart
                return jsonify({'volume_state': 'mounted' })

            elif str(status)  == '1':
                return jsonify({'volume_state': 'unmounted' })

            else:
                return jsonify({'volume_state': 'unavailable', 'output': stdout, 'stderr': stderr})


    def nfs_restart(self):

        logging.debug(f'Restarting NFS on: {self.distro_id}')

        if self.distro_id == 'centos':
            restart_command = 'sudo systemctl restart nfs-server'
        elif self.distro_id == 'ubuntu':
            restart_command = 'sudo systemctl restart nfs-kernel-server'
        else:
            restart_command = ''
        
        logging.debug(restart_command)

        status, stdout, stderr = run_command(restart_command)

        logging.debug(f'NFS status: {status}')
        logging.debug(f'NFS status stdout: {stdout}')
        logging.debug(f'NFS status stderr: {stderr}')

        if str(status) == '0':
            self.mount_nfs_on_wns()


    def mount_nfs_on_wns(self):

        for node in self.node_list:
            url = f'http://{node}:5000/luksctl_api_wn/v1.0/nfs-mount'
            response = requests.post(url, verify=False)
            response.raise_for_status()
            deserialized_response = json.loads(response.text)
            logging.debug(f'{node} NFS: {deserialized_response["nfs_state"]}')


    def docker_restart(self):

        restart_command = 'sudo systemctl restart docker'

        status, stdout, stderr = run_command(restart_command)

        logging.debug(f'Docker service status: {status}')
        logging.debug(f'Docker service stdout: {stdout}')
        logging.debug(f'Docker service stderr: {stderr}')



class wn:


    def __init__(self, nfs_mountpoint_list):

        self.nfs_mountpoint_list = nfs_mountpoint_list

    
    def write_api_config(self, luks_cryptdev_file='/etc/luks/luks-cryptdev.ini'):

        config = ConfigParser()

        config.add_section('luksctl_api')
        api_config = config['luksctl_api']

        api_config['NFS_MOUNTPOINT_LIST'] = json.dumps(self.nfs_mountpoint_list)

        with open(luks_cryptdev_file, 'a+') as f:
            config.write(f)


    def write_systemd_unit_file(self, service_file='/etc/systemd/system/luksctl-api.service', ssl=False):
        
        # Exit if command is not run as root
        if not os.geteuid() == 0:
            sys.exit('Error: write_systemd_unit_file must be run as root.')
        
        config = ConfigParser()
        config.optionxform = str
        
        config.add_section('Unit')
        config['Unit']['Description'] = 'Gunicorn instance to serve luksctl api server'
        config['Unit']['After'] = 'network.target'

        config.add_section('Service')
        config['Service']['User'] = 'luksctl_api_wn'
        config['Service']['Group'] = 'luksctl_api_wn'
        config['Service']['Working_directory'] = '/opt/luksctl_api/wn'
        config['Service']['Environment'] = '"PATH=/opt/luksctl_api/wn/venv/bin"'
        config['Service']['ExecStart'] = '/opt/luksctl_api/wn/venv/bin/gunicorn --workers 2 --bind 0.0.0.0:5000 -m 007 app:wn_app'
        
        config.add_section('Install')
        config['Install']['WantedBy'] = 'multi-user.target'

        with open(service_file, 'w') as sf:
            config.write(sf)


    def check_status(self):

        for mountpoint in self.nfs_mountpoint_list:
            logging.debug(f'{mountpoint}: {os.path.ismount(mountpoint)}')
            if not os.path.ismount(mountpoint):
                return False
        
        return True


    def get_status(self):

        logging.debug(self.nfs_mountpoint_list)
        if self.check_status():
            return jsonify({'nfs_state':'mounted'})
        else:
            return jsonify({'nfs_state':'unmounted'})


    def nfs_mount(self):

        if self.check_status():
            return jsonify({'nfs_state':'mounted'})
        
        mount_command = 'sudo mount -a -t nfs'

        logging.debug(mount_command)

        status, stdout, stderr = run_command(mount_command)

        logging.debug(f'NFS mount subprocess call status: {status}')
        logging.debug(f'NFS mount subprocess call stdout: {stdout}')
        logging.debug(f'NFS mount subprocess call stderr: {stderr}')

        return self.get_status()
