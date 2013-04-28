#!/bin/bash
DIR_BASE=/mnt/shared/orsec_data

NUM_PROCESSES=10
DATE_RANGE=2013-02--03
NUM_ADV_GUARDS=1
NUM_ADV_EXITS=1
ADV_TIME=1359763200
USERMODEL=bittorrent
NUM_SAMPLES=3000
TRACEFILE=$DIR_BASE/in/traces_processed.pickle

EXP_NAME=$USERMODEL.$DATE_RANGE.$NUM_ADV_GUARDS-$NUM_ADV_EXITS-$ADV_TIME-adv
NSF_DIR=$DIR_BASE/out/ns-$DATE_RANGE

i=1
while [ $i -le $NUM_PROCESSES ]
do
    (time pypy pathsim.py simulate $NSF_DIR $NUM_SAMPLES $TRACEFILE $USERMODEL 0 $NUM_ADV_GUARDS $NUM_ADV_EXITS $ADV_TIME) 2> $DIR_BASE/out/simulate/$EXP_NAME/simulate.$EXP_NAME.$NUM_SAMPLES-samples.$i.time | xz > $DIR_BASE/out/simulate/$EXP_NAME/simulate.$EXP_NAME.$NUM_SAMPLES-samples.$i.out.xz & 
    i=$(($i+1))
done
