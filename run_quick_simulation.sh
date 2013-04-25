#!/usr/bin/bash

NSF_DIR=out/network-state/slim/network-state-2013-03
NUM_SAMPLES=1
TRACEFILE=in/traces_processed.pickle
USERMODEL=simple
TESTING=0
ADV_GUARD_BW=0
ADV_EXIT_BW=0
ADV_TIME=0
pypy pathsim.py simulate $NSF_DIR $NUM_SAMPLES $TRACEFILE $USERMODEL $TESTING $ADV_GUARD_BW $ADV_EXIT_BW $ADV_TIME
