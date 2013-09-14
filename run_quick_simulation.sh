#!/bin/sh
BASE_DIR=$1
DATE_RANGE=$2
NSF_DIR=$BASE_DIR/out/network-state/slim/ns-$DATE_RANGE
NUM_SAMPLES=1
TRACEFILE=$BASE_DIR/in/traces_processed.pickle
USERMODEL="simple=1"
OUTPUT=0
ADV_GUARD_BW=0
ADV_EXIT_BW=0
ADV_TIME=0
NUM_ADV_GUARDS=0
pypy pathsim.py simulate $NSF_DIR $NUM_SAMPLES $TRACEFILE $USERMODEL $OUTPUT $ADV_GUARD_BW $ADV_EXIT_BW $ADV_TIME $NUM_ADV_GUARDS
simulate [nsf dir] [# samples] [tracefile] [user model] [output] [adv guard cons bw] [adv exit cons bw] [adv time] [num adv guards] [path selection alg] [num guards] [guard expiration]
