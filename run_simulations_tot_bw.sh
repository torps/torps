#!/bin/bash

# total bandwidth experiments
# allocation is 5:1 guard:exit
# total bws to test (tot: guard MBps / exit MBps; guard consensus bw / exit consensus bw)
# 	200: 174762666.0 / 34952533; 579920 / 157244
#	100: 87381333 / 17476266; 288115 / 76282
#	50: 43690666 / 8738133; 142213 / 35801
#	25: 21845333 / 4369066; 69262 / 15560
#	10: 8738133 / 1747626; 25492 / 3416
### again, doing conversion using linear regression coefficients
### coefficients determined from guard relays on 1/1/13
### a = 299.45192815560563
### b = 1104612.6683457776
### coefficients determined from exit relays 1/13-3/13
### a = 215.85762129136413
### b = 1010231.1684564484
### r_squared = 0.68600871839386535

BASE_DIR=/home/ajohnson/research/torps.git

TOT_PROCESSES=20
PARALLEL_PROCESSES=$1
DATE_RANGE=2013-01--03
OUTPUT=2
ADV_GUARD_BW=$2
ADV_EXIT_BW=$3
ADV_TIME=0
USERMODEL=typical
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
