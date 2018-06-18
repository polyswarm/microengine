#! /bin/bash

test(){
    sleep 1
    go run scratch.go
    test
}

#until [ "$gasLimit" -gt "$minGas" ]; do
#    >&2 echo "Gas limit of ${gasLimit} is too low - sleeping..."
#    sleep 1
#done
test
go run scratch.go
