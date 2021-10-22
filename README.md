# fastluks
Python scripts for storage encryption through LUKS. Converted into python from the bash scripts of [fast-luks](https://github.com/Laniakea-elixir-it/fast-luks)

For this package to work properly, both the installation and usage procedure must be run as superuser either in an Ubuntu or CentOS machine.

## Installation
The procedure to setup a virtual environment and install the package on a CentOS machine is the following:
```bash
yum install -y python3
python3 -m venv venv
. venv/bin/activate
pip install fastluks
```
To do the same on an Ubuntu machine:
```bash
apt-get update
apt-get install -y python3 python3-pip python3-venv
python3 -m venv venv
. venv/bin/activate
pip install fastluks
```

## Usage
To run the main script (which performs encryption and volume setup) with the default parameters, import the package and call the main_script function inside of a python session in the venv:
```python
import fastluks
fastluks.main_script()
```

The same result can be obtained directly from the command line after preparing and activating the virtual environment with the following command:
```bash
fastluks
```