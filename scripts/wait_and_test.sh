#!/bin/bash
./scripts/wait_for_it.sh $POLYSWARMD_HOST:$POLYSWARMD_PORT -t 0
microengine --testing 10 --keyfile docker/keyfile --password password --backend scratch
