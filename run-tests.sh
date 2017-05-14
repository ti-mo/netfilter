#!/bin/bash

# This script is executed within Docker context
# It is set as the entrypoint of the container by run-docker.sh
# When running on Linux, this can be invoked directly.

# Check if overalls is installed, and install it
if ! command -v overalls >/dev/null; then
    echo "I: Installing github.com/go-playground/overalls"
    go get github.com/go-playground/overalls
fi

echo "I: Running 'go get'"
go get

echo "I: Running tests"
overalls -project github.com/ti-mo/netfilter \
    -covermode atomic -concurrency 4 -debug \
    -- \
    -race -v -tags test
