#!/usr/bin/env bash -xe
mkdir -p $GOPATH/src/github.com/hyperledger/
cp -r $GOPATH/src/github.com/SmartBFT-Go/fabric $GOPATH/src/github.com/hyperledger/
go test -race ./orderer/consensus/smartbft/...
