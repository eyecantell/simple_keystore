# Use the Remote Development extension and /devcontainer/devcontainer.json 

# Use a base image with Python already installed
FROM python:3.10-slim

RUN apt-get update && apt-get install -y \
    curl \
    git \
    postgresql \
    sudo \
    tree \
    vim \
    && rm -rf /var/lib/apt/lists/*

# Install pip and the non-required development libraries
# Install pip if it's not already installed
RUN python -m ensurepip --default-pip && \
    pip install --no-cache-dir --upgrade pip
RUN pip install pdm
RUN pip install --upgrade ruff
RUN pip install GitPython
RUN pip install pytest

# Add .local/bin to PATH
ENV PATH=/home/developer/.local/bin:$PATH

# Set the working directory
WORKDIR /workspace/simple_keystore

# Install the Python dependencies listed in the requirements.txt file  
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create the developer user
RUN useradd -s /bin/bash -m developer
USER developer