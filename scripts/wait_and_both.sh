#!/bin/bash
./scripts/wait_for_it.sh $POLYSWARMD_HOST:$POLYSWARMD_PORT -t 0
microengine --keyfile docker/keyfile --password password --backend multi
