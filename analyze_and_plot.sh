#! /bin/bash

BASE_DIR=$1
USERMODEL=$2
DATE_RANGE=$3
ADV_GUARD_BW=$4
NUM_GUARDS=$5
ADV_EXIT_BW=$6
ADV_TIME=$7
EXTRA=$8

# for backwards compatibility: old experiments assumed one guard
if [ $NUM_GUARDS -eq 1 ]
then
    NUM_GUARDS_STR=""
else
    NUM_GUARDS_STR="-"$NUM_GUARDS
fi

EXP_NAME=$USERMODEL.$DATE_RANGE.$ADV_GUARD_BW$NUM_GUARDS_STR-$ADV_EXIT_BW-$ADV_TIME-adv$EXTRA

# move timing and logs to separate directories
mkdir -p $BASE_DIR/out/simulate/$EXP_NAME/logs
mkdir -p $BASE_DIR/out/simulate/$EXP_NAME/time
mv $BASE_DIR/out/simulate/$EXP_NAME/*.out $BASE_DIR/out/simulate/$EXP_NAME/logs 2> /dev/null
mv $BASE_DIR/out/simulate/$EXP_NAME/*.time $BASE_DIR/out/simulate/$EXP_NAME/time 2> /dev/null

# make output directories
mkdir -p $BASE_DIR/out/analyze/$EXP_NAME/data
mkdir -p $BASE_DIR/out/analyze/$EXP_NAME/plots

LOGS_IN=$BASE_DIR/out/simulate/$EXP_NAME/logs
DATA_OUT=$BASE_DIR/out/analyze/$EXP_NAME/data
PLOTS_OUT=$BASE_DIR/out/analyze/$EXP_NAME/plots

# analyze
pypy pathsim_analysis.py simulation-set $LOGS_IN $DATA_OUT $EXP_NAME

# plot
python pathsim_plot.py set $DATA_OUT $PLOTS_OUT

# archive for easy delivery
CUR_DIR_SAVE=$PWD
cd $PLOTS_OUT
tar cvf $EXP_NAME.tar *.pdf
bzip2 $EXP_NAME.tar
#cd $CUR_DIR_SAVE
