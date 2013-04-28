#!/bin/bash
DIR_BASE=/mnt/shared/orsec_data

NUM_PROCESSES=10
DATE_RANGE=2012-04--2013-03
NUM_ADV_GUARDS=2
NUM_ADV_EXITS=2
ADV_TIME=0
USERMODEL=typical
NUM_SAMPLES=5000
TRACEFILE=$DIR_BASE/in/traces_processed.pickle

EXP_NAME=$USERMODEL.$DATE_RANGE.$NUM_ADV_GUARDS-$NUM_ADV_EXITS-$ADV_TIME-adv
NSF_DIR=$DIR_BASE/out/ns-$DATE_RANGE

i=1
while [ $i -le $NUM_PROCESSES ]
do
    (time pypy pathsim.py simulate $NSF_DIR $NUM_SAMPLES $TRACEFILE $USERMODEL 0 $NUM_ADV_GUARDS $NUM_ADV_EXITS $ADV_TIME) 2> $DIR_BASE/out/simulate/$EXP_NAME/simulate.$EXP_NAME.$NUM_SAMPLES-samples.$i.time | xz > $DIR_BASE/out/simulate/$EXP_NAME/simulate.$EXP_NAME.$NUM_SAMPLES-samples.$i.out.xz & 
    i=$(($i+1))
done
