# Development Dockerfile for simple_keystore with PostgreSQL
# For use with VS Code Remote Development

FROM python:3.10-slim AS base

# Prevent apt from prompting for input
ENV DEBIAN_FRONTEND=noninteractive

# Combined apt call to minimize layers and install essential packages
RUN apt-get update && apt-get install -y \
    curl \
    git \
    redis-server \
    sudo \
    tree \
    vim \
    && rm -rf /var/lib/apt/lists/*

# Create the developer user and set up permissions
RUN useradd -s /bin/bash -m developer && \
    usermod -aG sudo developer && \
    echo "developer ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

# Switch to developer user for remaining operations
USER developer

# Set up Python environment
ENV PATH=/home/developer/.local/bin:$PATH
WORKDIR /workspace

# Install Python packages
RUN python -m ensurepip --default-pip && \
    pip install --no-cache-dir --upgrade pip

# Install development tools
RUN pip install --no-cache-dir \
    pdm \
    build \
    twine \
    ruff \
    GitPython \
    pytest \
    pytest-xdist

# Copy and install project requirements (note we need to keep requirements.txt and pyproject.toml in sync)
COPY --chown=developer:developer requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create a script to perform more setup including starting redis
USER root

COPY --chown=developer:developer <<EOF /usr/local/bin/docker-entrypoint.sh
#!/bin/bash

cd /mounted/dev/simple_keystore && pwd
#pip install -e . 
python ./scripts/copy_stuff_for_containers_home.py

sudo service redis-server start
sudo service redis-server status
redis-cli ping

EOF
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Switch back to developer user
USER developer

ENTRYPOINT ["/bin/bash", "-c", "/usr/local/bin/docker-entrypoint.sh && tail -f /dev/null"]