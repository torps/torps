#!/usr/bin/bash

NUM_PROCESSES=10
USERMODEL=irc
DATE_RANGE=2013-02--03
NUM_SAMPLES=5000
NUM_ADV_GUARDS=2
NUM_ADV_EXITS=2
ADV_TIME=1359763200
TRACEFILE=in/traces_processed.pickle

NSF_DIR=out/ns-$DATE_RANGE
EXP_NAME=$USERMODEL.$DATE_RANGE.$NUM_ADV_GUARDS-$NUM_ADV_EXITS-$ADV_TIME-adv

i=1
while [ $i -le $NUM_PROCESSES ]
do
    (time pypy pathsim.py simulate $NSF_DIR $NUM_SAMPLES $TRACEFILE $USERMODEL 0 $NUM_ADV_GUARDS $NUM_ADV_EXITS) 2> out/simulate/$EXP_NAME/simulate.$EXP_NAME.$NUM_SAMPLES-samples.$i.time | xz > out/simulate/$EXP_NAME/simulate.$EXP_NAME.$NUM_SAMPLES-samples.$i.out.xz &
    i=$(($i+1))
done
