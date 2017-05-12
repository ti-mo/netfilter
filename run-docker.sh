#!/bin/bash

# Script to set up Docker environment to test/develop the netfilter package.
# Inside Docker context, run-tests.sh is executed.

cname="netfilter"
cpath="/go/src/github.com/ti-mo/netfilter"
dstatus=$(docker ps -a --format "{{.Names}} {{.Status}}")

# --- Functions
gocheck() {
  if ! command -v go >/dev/null; then
    echo "E: 'go' not installed on host, exiting."
    exit
  fi
}

usage() {
  echo "$0 - run Docker development environment"
  echo ""
  echo "  :: This script sets up a Docker development environment."
  echo "  :: By default, it runs the test suite of all nested packages."
  echo ""
  echo "Usage: $0 [-h] [-b]"
  echo "    -h  This help."
  echo "    -b  Open browser on the host with coverage report."
  echo ""
  exit 1
}

# --- Parse Arguments
POST_BROWSER=""

while getopts "hb" opt; do
  case $opt in
    b)
      gocheck
      POST_BROWSER="yes"
      ;;
    h)
      usage
      exit
      ;;
  esac
done

# --- Docker Instantiation
if echo "$dstatus" | grep -q "^$cname[[:space:]]"; then
  if echo "$dstatus" | grep "^$cname[[:space:]]" | grep -q "Up"; then
    echo "Container '$cname' exists and is already running, exiting."
  else
    echo "Container '$cname' exists, starting.."

    docker start -i "$cname"

    echo "Container '$cname' terminated."
  fi
else
  echo "Container '$cname' not found, creating.."

  docker run -it --name netfilter --cap-add=NET_ADMIN \
    -v "$PWD":"$cpath" -w "$cpath" \
    golang "$cpath"/run-tests.sh

  echo "Container '$cname' terminated."
fi

# --- Post-run Tasks
if [ ! -z "$POST_BROWSER" ]; then
  echo "I: Opening browser with coverage report"
  go tool cover -html=overalls.coverprofile
fi
