# For development in VSCode, use the Remote Development extension and /devcontainer/devcontainer.json 
# To build the runtime container, use on the host from the samscrape dir: 
#   docker build -t get_latest_notices -f .devcontainer/Dockerfile .
#   docker run get_latest_notices


# Use a base image with Python already installed
FROM python:3.10-slim AS base

# Combined apt call to minimize number of layers
RUN apt-get update && apt-get install -y \
    curl \
    git \
    postgresql \
    sudo \
    tree \
    vim \
    && rm -rf /var/lib/apt/lists/*


# Add .local/bin to PATH
ENV PATH=/home/developer/.local/bin:$PATH

# Set the working directory
WORKDIR /mounted/dev
    
# Create the developer user and swith to developer user
RUN useradd -s /bin/bash -m developer
USER developer

# Install pip if it's not already installed
RUN python -m ensurepip --default-pip && \
    pip install --no-cache-dir --upgrade pip
    
# Install the Python dependencies listed in the requirements.txt file  
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

FROM base AS development

USER root

# Add the developer user to the sudo group
RUN usermod -aG sudo developer

# Optional: Configure passwordless sudo for the developer user
RUN echo "developer ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

USER developer
# Install additional tools
RUN pip install --no-cache-dir pdm build twine ruff GitPython pytest pytest-xdist
