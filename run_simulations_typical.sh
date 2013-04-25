#!/bin/bash

NUM_PROCESSES=10
DATE_RANGE=2013-01--03
TESTING=0
NUM_ADV_GUARDS=0
NUM_ADV_EXITS=0
ADV_TIME=0
USERMODEL=typical
NUM_SAMPLES=5000
TRACEFILE=in/users2-processed.traces.pickle
$PATH_ALG=tor

EXP_NAME=$USERMODEL.$DATE_RANGE.$NUM_ADV_GUARDS-$NUM_ADV_EXITS-$ADV_TIME-adv
NSF_DIR=out/ns-$DATE_RANGE

i=1
while [ $i -le $NUM_PROCESSES ]
do
    (time pypy pathsim.py simulate $NSF_DIR $NUM_SAMPLES $TRACEFILE $USERMODEL $TESTING $NUM_ADV_GUARDS $NUM_ADV_EXITS $ADV_TIME $PATH_ALG) 2> out/simulate/$EXP_NAME/simulate.$EXP_NAME.$NUM_SAMPLES-samples.$i.time | xz > out/simulate/$EXP_NAME/simulate.$EXP_NAME.$NUM_SAMPLES-samples.$i.out.xz & 
    i=$(($i+1))
done