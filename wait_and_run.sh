#! /bin/bash

./scripts/wait_for_it.sh $POLYSWARMD_HOST:$POLYSWARMD_PORT -t 60
go run scratch.go
