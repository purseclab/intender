#!/bin/bash

START=`head -n 2 $1 | tail -n 1 | awk '{print $1}' | grep -Po '[0-9]*'`
END=`tail -n 1 $1 | awk '{print $1}' | grep -Po '[0-9]*'`

TIME=$(($END - $START))

echo "$(($TIME / 1000 / 60 / 60))H $(($TIME / 1000 / 60 % 60))M $(($TIME / 1000 % 60)).$(($TIME % 1000))S"
