# Get own IP address
ip4=$(curl ifconfig.me)
echo "IP Address: $ip4"

# Copy files
# CODE_DIR="/home/ubuntu/FedTopK"
# cp -r /mnt/efs/fs1/FedTopK_Dev_working $CODE_DIR
# echo "Files copied"

# Move to root dir
# cd $CODE_DIR
#CODE_DIR="~/FedTopK/FedTopK_efs"
CODE_DIR="/mnt/efs/fs1/FedTopK_Dev_working"
echo "Moved to code dir $CODE_DIR"

# Set run config options
NUMBER_RUNS=$(grep num_runs $CODE_DIR/runtime/run.config | cut -d'=' -f2 | tr ',' ' ')
K_PARAM=$(grep k_param $CODE_DIR/runtime/run.config | cut -d'=' -f2 | tr ',' ' ')
DATASET=$(grep dataset $CODE_DIR/runtime/run.config | cut -d'=' -f2 | tr ',' ' ')
NORM_TYPE=$(grep norm_type $CODE_DIR/runtime/run.config | cut -d'=' -f2 | tr ',' ' ')
QUERY_WEIGHTS=$(grep query_weights $CODE_DIR/runtime/run.config | cut -d'=' -f2 | tr ',' ' ')
NUM_PARTIES=$(grep num_parties $CODE_DIR/runtime/run.config | cut -d'=' -f2)
NUM_WORKERS=$(grep num_workers $CODE_DIR/runtime/run.config | cut -d'=' -f2)
SECURITY_LEVEL=$(grep security_level $CODE_DIR/runtime/run.config | cut -d'=' -f2)
NUM_PARTICIPANTS=$(( ${NUM_PARTIES}+${NUM_WORKERS} ))
echo "Read run parameters k=$K_PARAM"

# Find IP address in host.list (to assign role number)
START_IND=1
ROLE_NUMBER_IND=$(grep -n "$ip4" $CODE_DIR/runtime/hosts.list | cut -d':' -f1)
echo "ROLE_NUMBER_IND:$ROLE_NUMBER_IND"
ROLE_NUMBER=$(( ${ROLE_NUMBER_IND}-${START_IND} ))

if [ "$ROLE_NUMBER" -lt "$NUM_PARTIES" ]; then
        ROLE="party"
elif [ "$ROLE_NUMBER" -lt "$NUM_PARTICIPANTS" ]; then
        ROLE="worker"
else
        ROLE="MANAGER"
fi

echo "   ROLE_NUMBER: $ROLE_NUMBER"
echo "          ROLE: $ROLE"

HOST_LIST_TMP=$(grep ubuntu $CODE_DIR/runtime/hosts.list | cut -d'@' -f2 | tr '\n' ',')
HOST_LIST=${HOST_LIST_TMP::-1}
echo "     HOST_LIST: $HOST_LIST"
#CODE_DIR=$PWD

# Execute shell script
if [ $ROLE != 'MANAGER' ]; then
        for r in $NUMBER_RUNS
        do
                echo "Starting run = $r"
                for k in $K_PARAM
                do
                        for dataset in $DATASET
                        do
                                for qw in $QUERY_WEIGHTS
                                do
                                        for nt in $NORM_TYPE
                                        do
                                                if [ $dataset == 'raisin' ]; then
                                                        echo "Starting k = $k and database = $dataset"
                                                        python3.11 -u $CODE_DIR/src/$ROLE.py $dataset $nt $qw $k $NUM_PARTIES $NUM_WORKERS 'vertical' $SECURITY_LEVEL $ROLE_NUMBER $HOST_LIST
                                                elif [ $dataset == 'housing' ]; then
                                                        echo "Starting k = $k and database = $dataset"
                                                        python3.11 -u $CODE_DIR/src/$ROLE.py $dataset $nt $qw $k $NUM_PARTIES $NUM_WORKERS 'vertical' $SECURITY_LEVEL $ROLE_NUMBER $HOST_LIST
                                                elif [ $dataset == 'dry_bean' ]; then
                                                        echo "Starting k = $k and database = $dataset"
                                                        python3.11 -u $CODE_DIR/src/$ROLE.py $dataset $nt $qw $k $NUM_PARTIES $NUM_WORKERS 'vertical' $SECURITY_LEVEL $ROLE_NUMBER $HOST_LIST
                                                elif [ $dataset == 'winequality' ]; then
                                                        echo "Starting k = $k and database = $dataset"
                                                        python3.11 -u $CODE_DIR/src/$ROLE.py $dataset $nt $qw $k $NUM_PARTIES $NUM_WORKERS 'vertical' $SECURITY_LEVEL $ROLE_NUMBER $HOST_LIST
                                                elif [ $dataset == 'shuttle' ]; then
                                                        echo "Starting k = $k and database = $dataset"
                                                        python3.11 -u $CODE_DIR/src/$ROLE.py $dataset $nt $qw $k $NUM_PARTIES $NUM_WORKERS 'vertical' $SECURITY_LEVEL $ROLE_NUMBER $HOST_LIST
                                                fi
                                done
                        done
                done
        done
else
        python3.11 $CODE_DIR/runtime/run_manager.py $NUM_PARTIES $NUM_WORKERS $NUM_PARTICIPANTS $HOST_LIST
fi
