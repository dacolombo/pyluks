# fastluks
Python scripts for storage encryption through LUKS. Converted into python from the bash scripts of [fast-luks](https://github.com/Laniakea-elixir-it/fast-luks)

For this package to work properly, both the installation and usage procedure must be run as superuser.

## Installation
To install this package in a python virtual environment, create and activate the venv, then install the package with pip:
```bash
python3 -m virtualenv venv
. venv/bin/activate
pip install fastluks
```

## Usage
To run the main script (which performs encryption and volume setup) with the default parameters, import the package and call the main_script function inside of a python session in the venv:
```python
import fastluks
fastluks.main_script()
```