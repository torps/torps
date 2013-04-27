#!/bin/bash

# user model experiments
# typical
# irc
# bittorrent
# pessimal user

BASE_DIR=/home/ajohnson/research/torps.git

TOT_PROCESSES=20
PARALLEL_PROCESSES=$1
DATE_RANGE=2013-01--03
OUTPUT=2
ADV_GUARD_BW=288115
ADV_EXIT_BW=76282
ADV_TIME=0
USERMODEL=$2
NUM_SAMPLES=5000
TRACEFILE=$BASE_DIR/in/users2-processed.traces.pickle
PATH_ALG=tor

EXP_NAME=$USERMODEL.$DATE_RANGE.$ADV_GUARD_BW-$ADV_EXIT_BW-$ADV_TIME-adv
NSF_DIR=$BASE_DIR/out/network-state/slim-filtered/ns-$DATE_RANGE
OUT_DIR=$BASE_DIR/out/simulate/$EXP_NAME

mkdir -p $OUT_DIR
i=1
while [ $i -le $TOT_PROCESSES ]
do
j=1
	while [[ $j -lt $PARALLEL_PROCESSES && $i -lt $TOT_PROCESSES ]]
	do
	# start these in parallel
    	(time pypy pathsim.py simulate $NSF_DIR $NUM_SAMPLES $TRACEFILE $USERMODEL $OUTPUT $ADV_GUARD_BW $ADV_EXIT_BW $ADV_TIME $PATH_ALG) 2> $OUT_DIR/simulate.$EXP_NAME.$NUM_SAMPLES-samples.$i.time 1> $OUT_DIR/simulate.$EXP_NAME.$NUM_SAMPLES-samples.$i.out &
	j=$(($j+1))
    	i=$(($i+1))
	done
# wait for this one to finish
(time pypy pathsim.py simulate $NSF_DIR $NUM_SAMPLES $TRACEFILE $USERMODEL $OUTPUT $ADV_GUARD_BW $ADV_EXIT_BW $ADV_TIME $PATH_ALG) 2> $OUT_DIR/simulate.$EXP_NAME.$NUM_SAMPLES-samples.$i.time 1> $OUT_DIR/simulate.$EXP_NAME.$NUM_SAMPLES-samples.$i.out
i=$(($i+1))
done
