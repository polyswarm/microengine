#! /bin/bash

./scripts/wait-for-it.sh $POLYSWARMD_HOST:$POLYSWARMD_PORT
go run scratch.go
