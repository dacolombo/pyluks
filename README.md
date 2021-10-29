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
To run the main script (which performs encryption and volume setup) with the default parameters, import the package and call the main_script function inside of a python session in the venv:
```python
import fastluks
fastluks.main_script()
```

The same result can be obtained directly from the command line after preparing and activating the virtual environment with the following command:
```bash
fastluks
```

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