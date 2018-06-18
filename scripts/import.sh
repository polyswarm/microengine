#!/usr/bin/env bash

mk_pkg(){
    echo $clean
    package_dir=$1
    # rm -rf $package_dir
    if [ ! -d $package_dir ]; then
        git clone https://github.com/$2.git
        mkdir -p $package_dir
        mv $3 $package_dir 
    fi
}

clean=$1

curr=$(pwd)
root=/go/src/github.com
# root=$HOME/.tmp/go/src/github.com
mk_pkg $root/ethereum              ethereum/go-ethereum go-ethereum
mk_pkg $root/gorilla               gorilla/websocket    websocket
mk_pkg $root/mr-tron/base58        mr-tron/base58       base58
mk_pkg $root/satori/go.uuid        satori/go.uuid       go.uuid 

cd $root
cp mr-tron/base58/base58/base58/*  mr-tron/base58
cp satori/go.uuid/go.uuid/*        satori/go.uuid

cd $curr
