#!/bin/bash

ARGS="--models=7rules --secrecy --no-buffer"

ls -1 ~/src/ikev2/pp-results/ikev*.spdl | xargs -n 1 bsub -J "IKE-CB" -Jd "IKE compromise batch" -W 8:00 -N ./test-adversary-models.py $ARGS $*

