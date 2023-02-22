#!/bin/bash

if [ $# -ne 1 ]; then
    echo "Usage: $0 [file]"
fi

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

HOSTS=`curl -X GET http://localhost:5000/topology -H "Content-Type: application/json" | jq -r '.topology.hosts | .[] | .mac '`

HOST1=`echo $HOSTS | awk '{print $1}'`
HOST2=`echo $HOSTS | awk '{print $2}'`
HOST_TAB='                    '
cat $SCRIPT_DIR/h2h-begin.txt > $1
echo "$HOST_TAB\"one\": \"${HOST1^^}/None\"," >> $1
echo "$HOST_TAB\"two\": \"${HOST2^^}/None\"" >> $1
cat $SCRIPT_DIR/h2h-end.txt >> $1

