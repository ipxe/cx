#!/bin/sh

set -e
set -x

# (Re)build extensions
#
python3 setup.py build_ext -f

# Run test suite with coverage checks
#
python3 -m coverage erase
python3 -m coverage run --branch --source libcx setup.py test
python3 -m coverage report --show-missing

# Run pycodestyle
#
python3 -m pycodestyle libcx test

# Run flake8
#
python3 -m flake8 libcx test

# Run pylint
#
python3 -m pylint libcx test
