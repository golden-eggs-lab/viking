FROM ubuntu:22.04

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONPATH=/workspace/src
ENV LD_LIBRARY_PATH=/usr/local/lib

# Install system dependencies and Python 3.11
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y \
    cmake \
    g++ \
    build-essential \
    git \
    curl \
    wget \
    software-properties-common \
    && add-apt-repository ppa:deadsnakes/ppa -y \
    && apt-get update \
    && apt-get install -y \
    python3.11 \
    python3.11-venv \
    python3.11-dev \
    python3.11-distutils \
    python3-pip \
    pssh \
    openssh-client \
    openssh-server \
    sshpass \
    iputils-ping \
    net-tools \
    sudo \
    && rm -rf /var/lib/apt/lists/* \
    && echo "Python 3.11 installation check:" \
    && python3.11 --version \
    && which python3.11 \
    && echo "Installing pip for Python 3.11..." \
    && curl -sS https://bootstrap.pypa.io/get-pip.py -o /tmp/get-pip.py \
    && python3.11 /tmp/get-pip.py \
    && echo "Python 3.11 installation completed successfully"

# Clone and build SEAL early to improve cache reuse
RUN git clone https://github.com/microsoft/SEAL.git /tmp/SEAL && \
    cd /tmp/SEAL && git checkout v4.0.0 && \
    mkdir build && cd build && \
    cmake .. -DBUILD_SHARED_LIBS=ON -DCMAKE_BUILD_TYPE=Release && \
    make -j$(nproc) && \
    make install && \
    rm -rf /tmp/SEAL

# Ensure library path includes SEAL
ENV LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

# Create ubuntu user (to match the script expectations)
RUN useradd -m -s /bin/bash ubuntu
RUN echo "ubuntu ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Set up SSH
RUN mkdir -p /var/run/sshd
RUN echo 'root:ubuntu' | chpasswd
RUN echo 'ubuntu:ubuntu' | chpasswd
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Set working directory
WORKDIR /workspace

# Install Python deps from requirements first (better cache)
COPY --chown=ubuntu:ubuntu requirements.txt requirements.txt

# Create and activate virtual environment (Kenv) using Python 3.11
RUN chown ubuntu:ubuntu /workspace
USER ubuntu
RUN echo "Checking Python 3.11 installation..." && \
    ls -la /usr/bin/python* && \
    echo "Creating virtual environment with Python 3.11..." && \
    /usr/bin/python3.11 -m venv /workspace/Kenv && \
    echo "Checking virtual environment Python version..." && \
    /workspace/Kenv/bin/python --version && \
    echo "Upgrading pip..." && \
    /workspace/Kenv/bin/pip install --upgrade pip && \
    echo "Installing Python packages from requirements.txt..." && \
    /workspace/Kenv/bin/pip install -r requirements.txt --verbose
ENV PATH="/workspace/Kenv/bin:$PATH"

# Now copy the rest of the project files (changes here won't rebuild deps)
USER root
COPY --chown=ubuntu:ubuntu . .

 

# Create necessary directories
RUN mkdir -p /home/ubuntu/FedTopK /mnt/efs/fs1

# Switch to ubuntu user
USER ubuntu

# Default command (can be overridden)
CMD ["/bin/bash"]
