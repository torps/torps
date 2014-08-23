#!/bin/bash

# total bandwidth experiments
# allocation is 5:1 guard:exit
# total bws to test (tot: guard MBps / exit MBps; guard consensus bw / exit consensus bw)

### doing conversion using linear regression coefficients
### coefficients determined from guard relays on 1/1/13
### guard_a = 299.45192815560563
### guard_b = 1104612.6683457776
### guard_r_squared = 0.74124917207592156
### coefficients determined from exit relays 1/13-3/13
### exit_a = 215.85762129136413
### exit_b = 1010231.1684564484
### exit_r_squared = 0.68600871839386535

# 	200: 174762666.0 / 34952533; 579920 / 157244
#	100: 87381333 / 17476266; 288115 / 76282
#	50: 43690666 / 8738133; 142213 / 35801
#	25: 21845333 / 4369066; 69262 / 15560
#	10: 8738133 / 1747626; 25492 / 3416

### coefficients determined from guard relays on 10/12 - 3/13
# guard_a = 191.94548955003913
# guard_b = 1368281.674385923
# guard_r_squared = 0.70610513990802581
### coefficients determined from exit relays 10/12 - 3/13
# exit_a = 200.49050736264786
# exit_b = 1029509.7491675143
# exit_r_squared = 0.69361698646482162

# using regression on 10/12-3/13 data
# 	200: 174762666.0 / 34952533; 903352 / 169200
#	100: 87381333 / 17476266; 448112 / 82033
#	50: 43690666 / 8738133; 220492 / 38449
#	25: 21845333 / 4369066; 106682 / 16657
#	10: 8738133 / 1747626; 38396 / 3582


BASE_DIR=/home/ajohnson/research/torps.git

TOT_PROCESSES=20
PARALLEL_PROCESSES=$1
DATE_RANGE=$2
NSF_TYPE=$3
OUTPUT="relay-adv"
ADV_GUARD_BW=$4
ADV_EXIT_BW=$5
ADV_TIME=0
NUM_ADV_GUARDS=1
NUM_ADV_EXITS=1
USERMODEL=typical
NUM_SAMPLES=5000
TRACEFILE=$BASE_DIR/in/users2-processed.traces.pickle
LOGLEVEL="INFO"
PATH_ALG=tor

EXP_NAME=$USERMODEL.$DATE_RANGE.$ADV_GUARD_BW-$NUM_ADV_GUARDS-$ADV_EXIT_BW-$ADV_TIME-adv
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
    	(time pypy pathsim.py simulate --nsf_dir $NSF_DIR --num_samples $NUM_SAMPLES --trace_file $TRACEFILE --user_model $USERMODEL --format $OUTPUT --adv_guard_cons_bw $ADV_GUARD_BW --adv_exit_exit_cons_bw $ADV_EXIT_BW --adv_time $ADV_TIME --num_adv_guards $NUM_ADV_GUARDS --num_adv_exits $NUM_ADV_EXITS --loglevel $LOGLEVEL $PATH_ALG) 2> $OUT_DIR/simulate.$EXP_NAME.$NUM_SAMPLES-samples.$i.time 1> $OUT_DIR/simulate.$EXP_NAME.$NUM_SAMPLES-samples.$i.out &
	j=$(($j+1))
    	i=$(($i+1))
	done
# wait for this one to finish
(time pypy pathsim.py simulate --nsf_dir $NSF_DIR --num_samples $NUM_SAMPLES --trace_file $TRACEFILE --user_model $USERMODEL --format $OUTPUT --adv_guard_cons_bw $ADV_GUARD_BW --adv_exit_exit_cons_bw $ADV_EXIT_BW --adv_time $ADV_TIME --num_adv_guards $NUM_ADV_GUARDS --num_adv_exits $NUM_ADV_EXITS --loglevel $LOGLEVEL $PATH_ALG) 2> $OUT_DIR/simulate.$EXP_NAME.$NUM_SAMPLES-samples.$i.time 1> $OUT_DIR/simulate.$EXP_NAME.$NUM_SAMPLES-samples.$i.out
i=$(($i+1))
done