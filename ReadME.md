## FedTopK: Secure Top-K Queries on Vertical Data Federations

Source code for FedTopK, which is a system for answering top-k join queries securely and efficiently over a vertical data federation. It consists of a set of novel cryptographic constructs that are specialized for the operators in distributed top-k query answering under a uniform framework, and guarantees end-to-end semantic security against semi-honest adversaries.

The submission to VLDB '26 is currently under review, the PDF copy of our paper will be released later.

## Dependencies
FedTopK has been tested on Python version 3.11. Installing FedTopK requires Python 3.11 or a later version.
### For Linux
```bash
apt install -y \
    build-essential \
    python3.11 \
    python3.11-dev \
    python3.11-venv \
    python3.11-distutils \
    cmake \
    curl \
    pssh \
    ssh
```
### For macOS
```bash
brew install \
    cmake \
    python@3.11 \
    curl \
    pssh \
    openssh

xcode-select --install
```
Each party or worker participating in the FedTopK system should be configured as an instance, and the dependencies are required on all parties and workers.

Additionally, ensure that all required ports-**2000, 3000, and 3999** (default)—are open and accessible between each instance, allowing for proper communication across the network.
## Installation
### Clone repository
```bash
git clone --recurse-submodules https://github.com/golden-eggs-lab/fedtopk.git

cd fedtopk
```
### Create virtual environment
```bash
python3.11 -m venv fvenv

source /fvenv/bin/activate

pip install -Ur requirements.txt
```
### Generate binding libraries
```bash
./runtime/binding_gen.sh
```

## Role Assignment
The FedTopK system utilizes multiple instances, each assigned a specific role based on the order of IP addresses in the ``hosts.list`` file
### Party
A Party  is an instance that holds a vertically partitioned dataset. The script prioritizes assigning this role first.
### Worker
A Worker serves as part of a mixnet, a cryptographic structure designed to enable efficient multi-party computation. Workers are assigned sequentially after parties.
### Manager
In this experimental simulation, the Manager orchestrates the activities of both parties and workers, distributing datasets to streamline the preprocessing stage. This role is optional and is assigned to the next available instance once the parties and workers have been designated.

## Quick Start
All commands in this section are assumed to be executed in the root directory of **FedTopK**. Ensure that you go through the steps above on all instances to avoid missing any dependencies.

To modify or confirm the configurations, refer to the following files:
  - **`$root/runtime/run.config`**: Contains the dataset name, security level, and `k` value for FedTopK experiments.
  - **`$root/runtime/hosts.list`**: Specifies IP addresses of participating parties or workers for the distributed setup.

### Running FedTopK with Example Queries

Before running the example queries, please ensure that you have a total of 7 available instances with all dependencies and necessary libraries pre-installed.

FedTopK includes example configuration files in the ``$root/runtime/`` folder to help you get started. The ``run.config`` file is preconfigured with an example query that uses a 3-party, 3-worker setup with the winequality dataset and function F2, operating in plaintext mode.

With configurations verified, execute the following command from the root directory to launch the experiment on any of instances listed in the ``hosts.list``. You only need to run this command on a single instance, the script will automatically manage all necessary instances listed in ``hosts.list`` and display the output directly in your terminal:

```bash
./runtime/run_ec2.sh
```

### Running FedTopK with Your Own Data and Schema
#### Step 1: Prepare and Replace Dataset
You can add any dataset(in CSV format) for testing into the `$root/data/processed` folder. In the configuration file `$root/runtime/run.config`, you can only modify the logged in instance's config files to update the dataset name to match your added dataset. The program will populate the specific dataset, and manager instance will distribute the dataset evenly across all parties to simulate the distributed system setting.
#### Step 2: Run FedTopK
Similar to the example query configuration, you can adjust any parameters in `$root/runtime/run.config` on the instance where the script will be executed. Once configured, execute the following command to run the program on any of instance listed in the ``hosts.list``:

```bash
./runtime/run_ec2.sh
```
### Running Benchmark with Existing MPC Frameworks
More details are in [README.md](baseline/README.md)

## Acknowledgement and License
FedTopK is built on the top of [SEAL](https://github.com/microsoft/SEAL) and [SealPIR](https://github.com/microsoft/SealPIR), and the baseline experiments conver multiple existing SOTA multiple party computation framework, the details are in `baseline/README.md` references section.

[MIT LICENSE](LICENSE)

## Question / Help / Bug
If you encounter any problems while using FedTopK and need our help, please [click](https://github.com/golden-eggs-lab/fedtopk/issues/new/choose) to report the problem.

