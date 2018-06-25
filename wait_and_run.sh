#! /bin/bash

./scripts/wait_for_it.sh $POLYSWARMD_HOST:$POLYSWARMD_PORT
go run scratch.go
