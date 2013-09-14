#!/bin/bash

# congestion-aware tor experiment 

BASE_DIR=$1

TOT_PROCESSES=$2
PARALLEL_PROCESSES=$3
DATE_RANGE=$4
NSF_TYPE=$5
OUTPUT=2
ADV_GUARD_BW=$6
ADV_EXIT_BW=$7
ADV_TIME=0
NUM_ADV_GUARDS=$8
USERMODEL=$9
NUM_SAMPLES=${10}
TRACEFILE=$BASE_DIR/in/users2-processed.traces.pickle
PATH_ALG=cat
CONGFILE=$BASE_DIR/in/congestion.cator.pickle

EXP_NAME=$USERMODEL.$DATE_RANGE.$ADV_GUARD_BW-$NUM_ADV_GUARDS-$ADV_EXIT_BW-$ADV_TIME-adv.cat
NSF_DIR=$BASE_DIR/out/network-state/$NSF_TYPE/ns-$DATE_RANGE
OUT_DIR=$BASE_DIR/out/simulate/$EXP_NAME
mkdir -p $OUT_DIR
i=1
while [ $i -le $TOT_PROCESSES ]
do
j=1
	while [[ $j -lt $PARALLEL_PROCESSES && $i -lt $TOT_PROCESSES ]]
	do
	# start these in parallel
    	(time pypy pathsim.py simulate $NSF_DIR $NUM_SAMPLES $TRACEFILE $USERMODEL $OUTPUT $ADV_GUARD_BW $ADV_EXIT_BW $ADV_TIME $NUM_ADV_GUARDS $PATH_ALG $CONGFILE) 2> $OUT_DIR/simulate.$EXP_NAME.$NUM_SAMPLES-samples.$i.time 1> $OUT_DIR/simulate.$EXP_NAME.$NUM_SAMPLES-samples.$i.out &
	j=$(($j+1))
    	i=$(($i+1))
	done
# wait for this one to finish
(time pypy pathsim.py simulate $NSF_DIR $NUM_SAMPLES $TRACEFILE $USERMODEL $OUTPUT $ADV_GUARD_BW $ADV_EXIT_BW $ADV_TIME $NUM_ADV_GUARDS $PATH_ALG $CONGFILE) 2> $OUT_DIR/simulate.$EXP_NAME.$NUM_SAMPLES-samples.$i.time 1> $OUT_DIR/simulate.$EXP_NAME.$NUM_SAMPLES-samples.$i.out
i=$(($i+1))
done
