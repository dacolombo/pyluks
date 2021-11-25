# fastluks
Python scripts for storage encryption through LUKS. Converted into a python package from [fast-luks](https://github.com/Laniakea-elixir-it/fast-luks) and [luksctl](https://github.com/Laniakea-elixir-it/luksctl)

For this package to work properly, both the installation and usage procedure must be run as superuser either in an Ubuntu or CentOS machine.

## Installation
The procedure to setup a virtual environment and install the package on CentOS is the following:
```bash
yum install -y python3
python3 -m venv venv
. venv/bin/activate
pip install fastluks
```
To do the same on Ubuntu:
```bash
apt-get update
apt-get install -y python3 python3-pip python3-venv
python3 -m venv venv
. venv/bin/activate
pip install fastluks
```

## Usage: fastluks
To perform encryption and volume setup with default parameters, the `fastluks` command can be used inside the virtual environment:
```bash
fastluks
```
The encryption passphrase can be stored locally and/or on Hashicorp Vault.
- To store the passphrase locally:
```bash
fastluks --save-passphrase-locally
```
- To store the passphrase on Vault, the flag `--vault` must be used with the required arguments specified:
<pre>
fastluks --vault --vault-url <i>url</i> --wrapping-token <i>token</i> --secret-path <i>path</i> --user-key <i>key</i>
</pre>




## Usage: luksctl
In order to manage a volume encrypted with fastluks, the command `luksctl` can be used from the command line:
```bash
# Display volume status
luksctl status

# Open encrypted volume
luksctl open

# Close encrypted volume
luksctl close
```