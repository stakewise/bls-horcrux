#!/bin/bash

if [[ "$OSTYPE" == "linux"* ]] || [[ "$OSTYPE" == "linux-android"* ]] || [[ "$OSTYPE" == "darwin"* ]]; then
    echo $OSTYPE
    if [[ $1 == "install" ]]; then
        echo "Installing dependencies..."
        pip3 install -r requirements/prod.txt
        exit 1
    fi
    echo "Running BLS horcrux..."
    python3 ./horcrux.py "$@"

elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
    echo $OSTYPE
    if [[ $1 == "install" ]]; then
        echo "Installing dependencies..."
        pip install -r requirements/prod.txt
        exit 1
    fi
    echo "Running BLS horcrux..."
    python ./horcrux.py "$@"

else
    echo "Sorry, to run BLS horcrux on" $(uname -s)", please see the trouble-shooting on https://github.com/stakewise/bls-horcrux"
    exit 1

fi
