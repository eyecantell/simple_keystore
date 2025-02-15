FROM python:3.10-slim

# Install system dependencies first
# build-essential, libsffi-dev, libssl-dev are for cryptography module
RUN apt-get update && apt-get install -y \
    curl \
    git \
    postgresql \
    sudo \
    tree \
    vim \
    build-essential \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create the developer user
RUN useradd -s /bin/bash -m developer
RUN usermod -aG sudo developer

# Set the working directory
WORKDIR /workspace/simple_keystore

# Switch to developer user
USER developer

# Now set the PATH for the developer user
ENV PATH=/home/developer/.local/bin:$PATH

# Install pip and upgrade it
RUN python -m ensurepip --default-pip && \
    pip install --no-cache-dir --upgrade pip

# Copy requirements and install dependencies
COPY --chown=developer:developer requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install additional tools
RUN pip install --no-cache-dir pdm build twine ruff GitPython pytest pytest-xdist