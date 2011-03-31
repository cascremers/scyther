#!/bin/sh

./batcher.sh -m 2 --all-types --self-communication ~/src/ikev2/pp-results/mpa/ikev1*.spdl
./batcher.sh -m 2 --all-types --self-communication ~/src/ikev2/pp-results/mpa/ikev2*.spdl

