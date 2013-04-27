#!/bin/bash

#bandwidth experiments

#ratio   guard bw        exit bw         guard cons bw        exit cons bw
#1:1     52428800        52428800        171394               238205                  
#5:1     87381333        17476267        288115               76282
#10:1    95325091        9532509         314643               39481
#50:1    102801568       2056031         339610               4845

### coefficients determined from guard relays on 1/1/13
### a = 299.45192815560563
### b = 1104612.6683457776

### coefficients determined from exit relays 1/13-3/13
### a = 215.85762129136413
### b = 1010231.1684564484
### r_squared = 0.68600871839386535

BASE_DIR=/mnt/ram

NUM_PROCESSES=20
DATE_RANGE=2013-01--03
OUTPUT=2
#ADV_GUARD_BW=0
#ADV_EXIT_BW=0
ADV_TIME=0
USERMODEL=typical
NUM_SAMPLES=5000
TRACEFILE=$BASE_DIR/in/users2-processed.traces.pickle
PATH_ALG=tor

EXP_NAME=$USERMODEL.$DATE_RANGE.$1-$2-$ADV_TIME-adv
NSF_DIR=$BASE_DIR/out/network-state/slim-filtered/ns-$DATE_RANGE
i=1
while [ $i -le $NUM_PROCESSES ]
do
    (time pypy pathsim.py simulate $NSF_DIR $NUM_SAMPLES $TRACEFILE $USERMODEL $OUTPUT $1 $2 $ADV_TIME $PATH_ALG) 2> $BASE_DIR/out/simulate/$EXP_NAME/simulate.$EXP_NAME.$NUM_SAMPLES-samples.$i.time 1> $BASE_DIR/out/simulate/$EXP_NAME/simulate.$EXP_NAME.$NUM_SAMPLES-samples.$i.out 
    i=$(($i+1))
done
