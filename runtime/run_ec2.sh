# GitHub-based setup (replaces EFS copy)
# Configure these as needed or export before running
REPO_URL=${REPO_URL:-"https://github.com/your-org/FedTopK_Dev_working.git"}
REPO_BRANCH=${REPO_BRANCH:-"main"}
REPO_DIR=${REPO_DIR:-"/home/ubuntu/FedTopK_Dev_working"}

# Clone or update repository
if [ ! -d "$REPO_DIR/.git" ]; then
    mkdir -p "$(dirname "$REPO_DIR")"
    git clone --branch "$REPO_BRANCH" "$REPO_URL" "$REPO_DIR"
else
    cd "$REPO_DIR"
    git fetch --all --prune
    git checkout "$REPO_BRANCH"
    git pull --ff-only origin "$REPO_BRANCH"
fi

# Navigate to repository and activate venv (assumes venv exists under repo)
cd "$REPO_DIR"
if [ -f "Kenv/bin/activate" ]; then
    source Kenv/bin/activate
fi

# Get own IP address (public). For private LAN, use the commented eth0 method instead
# ip4=$(/sbin/ip -o -4 addr list eth0 | awk '{print $4}' | cut -d/ -f1)
ip4=$(curl -s ifconfig.me)
echo "IP Address: $ip4"

### Set run config options
NUMBER_RUNS=$(grep -E '^num_runs=' runtime/run.config | cut -d'=' -f2)
K_PARAM=$(grep -E '^k_param=' runtime/run.config | cut -d'=' -f2)
DATASET=$(grep -E '^dataset=' runtime/run.config | cut -d'=' -f2)
NORM_TYPE=$(grep -E '^norm_type=' runtime/run.config | cut -d'=' -f2)
QUERY_WEIGHTS=$(grep -E '^query_weights=' runtime/run.config | cut -d'=' -f2)
NUM_PARTIES=$(grep -E '^num_parties=' runtime/run.config | cut -d'=' -f2)
NUM_WORKERS=$(grep -E '^num_workers=' runtime/run.config | cut -d'=' -f2)
SECURITY_LEVEL=$(grep -E '^security_level=' runtime/run.config | cut -d'=' -f2)
NUM_PARTICIPANTS=$(( ${NUM_PARTIES}+${NUM_WORKERS} ))

# Output config options to CLI
echo "   NUMBER_RUNS: $NUMBER_RUNS"
echo "       K_PARAM: $K_PARAM"
echo "       DATASET: $DATASET"
echo "     NORM_TYPE: $NORM_TYPE"
echo " QUERY_WEIGHTS: $QUERY_WEIGHTS"
echo "   NUM_PARTIES: $NUM_PARTIES"
echo "   NUM_WORKERS: $NUM_WORKERS"
echo "SECURITY_LEVEL: $SECURITY_LEVEL"
echo "    NUM_PARTIC: $NUM_PARTICIPANTS"

# Find IP address in host.list (to assign role number)
START_IND=1
ROLE_NUMBER_IND=$(grep -n "$ip4" runtime/hosts.list | cut -d':' -f1)
echo "ROLE_NUMBER_IND:$ROLE_NUMBER_IND"
ROLE_NUMBER=$(( ${ROLE_NUMBER_IND}-${START_IND} ))
CODE_DIR=$PWD

CMD="$CODE_DIR/runtime/test_run.sh"
parallel-ssh -P -t 0 -h runtime/hosts.list -O StrictHostKeyChecking=no -x '-i MacBook_JC.pem' $CMD
