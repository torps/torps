#! /bin/bash

BASE_DIR=$1
USERMODEL=$2
DATE_RANGE=$3
ADV_GUARD_BW=$4
ADV_EXIT_BW=$5
ADV_TIME=$6

EXP_NAME=$USERMODEL.$DATE_RANGE.$ADV_GUARD-$ADV_EXIT-$ADV_TIME-adv

# move timing and logs to separate directories
mkdir -p $BASE_DIR/out/simulate/$EXP_NAME/logs
mkdir -p $BASE_DIR/out/simulate/$EXP_NAME/time
mv $BASE_DIR/out/simulate/$EXP_NAME/*.out $BASE_DIR/out/simulate/$EXP_NAME/logs
mv $BASE_DIR/out/simulate/$EXP_NAME/*.time $BASE_DIR/out/simulate/$EXP_NAME/time

# make output directories
mkdir -p $BASE_DIR/out/analyze/$EXP_NAME/data
mkdir -p $BASE_DIR/out/analyze/$EXP_NAME/plots

LOGS_IN=$BASE_DIR/out/simulate/$EXP_NAME/logs
DATA_OUT=$BASE_DIR/out/analyze/$EXP_NAME/data
PLOTS_OUT=$BASE_DIR/out/analyze/$EXP_NAME/plots

# analyze
pathsim_analysis.py simulation-set $LOGS_IN $DATA_OUT $EXP_NAME

# plot
pathsim_plot.py set $DATA_OUT $PLOTS_OUT