#!/bin/bash

# Script to set up Docker environment to test/develop the netfilter package.
# Inside Docker context, run-tests.sh is executed.

cname="netfilter"
cpath="/go/src/github.com/ti-mo/netfilter"
dstatus=$(docker ps -a --format "{{.Names}} {{.Status}}")

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
