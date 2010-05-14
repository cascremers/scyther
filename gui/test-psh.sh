#!/bin/sh

./test-adversary-models.py --models=7rules --secrecy        Protocols/*.spdl Protocols/AdversaryModels/*.spdl 
./test-adversary-models.py --models=7rules --authentication Protocols/*.spdl 
