#!/usr/bin/env bash -xe

go get -u golang.org/x/tools/cmd/goimports

unformatted=$(find . -name "*.go" | grep -v "^./vendor" | grep -v "pb.go" | grep "./orderer" | xargs gofmt -l)

if [[ $unformatted == "" ]];then
    echo "gofmt checks passed"
else
    echo "The following files needs gofmt:"
    echo "$unformatted"
    exit 1
fi

unformatted=$(git show --name-only | grep ".go$" | grep -v "^./vendor" | grep -v "pb.go" | grep "./orderer" |xargs goimports -l)

if [[ $unformatted == "" ]];then
    echo "goimports checks passed"
else
    echo "The following files needs goimports:"
    echo "$unformatted"
    exit 1
fi


echo "Running unit tests"
go test -race ./orderer/consensus/smartbft/...
if [[ $? -ne 0 ]];then
    echo "unit tests failed"
    exit 1
fi

echo "Pulling docker pull hyperledger/fabric-ccenv:latest"
docker pull hyperledger/fabric-ccenv:latest

echo "Installing Ginkgo :( "
go get github.com/onsi/ginkgo/ginkgo
go get github.com/onsi/gomega/...

echo "Running integration tests"
cd integration/smartbft
ginkgo --focus "smartbft multiple nodes"

if [[ $? -ne 0 ]];then
    echo "integration tests failed"
    exit 1
fi
