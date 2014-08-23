#!/bin/bash

#bandwidth allocation experiments

### coefficients from guard relays on 1/1/13, cf network_analysis.py
### a = 299.45192815560563
### b = 1104612.6683457776
### r_squared = 0.74124917207592156

### coefficients from exit relays 1/13-3/13, cf network_analysis.py
### a = 215.85762129136413
### b = 1010231.1684564484
### r_squared = 0.68600871839386535

#ratio   guard bw        exit bw         guard cons bw        exit cons bw
#1:1     52428800        52428800        171394               238205
#2:1     69905067        34952533        229755               157244
#5:1     87381333        17476267        288115               76282
#10:1    95325091        9532509         314643               39481
#50:1    102801568       2056031         339610               4845


### coefficients from guard relays 10/12-3/13, cf network_analysis.py
# exit_a = 200.49050736264786
# exit_b = 1029509.7491675143
# exit_r_squared = 0.69361698646482162

### coefficients  from exit relays 10/12-3/13, cf network_analysis.py
# guard_a = 191.94548955003913
# guard_b = 1368281.674385923
# guard_r_squared = 0.70610513990802581

#ratio   guard bw        exit bw         guard cons bw        exit cons bw
#1:1     52428800        52428800        266016               256368
#2:1     69905067        34952533        357064               169200
#5:1     87381333        17476267        448112               82033
#10:1    95325091        9532509         489497               42411
#50:1    102801568       2056031         528448               5120



BASE_DIR=/home/ajohnson/research/torps.git

NUM_PROCESSES=20
DATE_RANGE=$1
NSF_TYPE=$2
OUTPUT="relay-adv"
ADV_GUARD_BW=$3
ADV_EXIT_BW=$4
ADV_TIME=0
NUM_ADV_GUARDS=1
NUM_ADV_EXITS=1
USERMODEL=typical
NUM_SAMPLES=5000
TRACEFILE=$BASE_DIR/in/users2-processed.traces.pickle
LOGLEVEL="INFO"
PATH_ALG=tor

EXP_NAME=$USERMODEL.$DATE_RANGE.$ADV_GUARD_BW-$ADV_EXIT_BW-$ADV_TIM-adv
NSF_DIR=$BASE_DIR/out/network-state/$NSF_TYPE/ns-$DATE_RANGE

# make output directory
OUT_DIR=$BASE_DIR/out/simulate/$EXP_NAME
mkdir -p $OUT_DIR
 
i=1
while [ $i -le $NUM_PROCESSES ]
do
    (time pypy pathsim.py simulate --nsf_dir $NSF_DIR --num_samples $NUM_SAMPLES --trace_file $TRACEFILE --user_model $USERMODEL --format $OUTPUT --adv_guard_cons_bw $ADV_GUARD_BW --adv_exit_cons_bw $ADV_EXIT_BW --adv_time $ADV_TIME --num_adv_guards $NUM_ADV_GUARDS --num_adv_exits $NUM_ADV_EXITS --loglevel $LOGLEVEL $PATH_ALG) 2> $OUT_DIR/simulate.$EXP_NAME.$NUM_SAMPLES-samples.$i.time 1> $OUT_DIR/simulate.$EXP_NAME.$NUM_SAMPLES-samples.$i.out &
    i=$(($i+1))
done