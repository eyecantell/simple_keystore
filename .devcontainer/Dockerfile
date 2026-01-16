# Development Dockerfile for simple_keystore
# For use with VS Code Remote Development

FROM python:3.10-slim AS base

# Prevent apt from prompting for input
ENV DEBIAN_FRONTEND=noninteractive

# Install essential packages
RUN apt-get update && apt-get install -y \
    curl \
    gh \
    git \
    locales \
    npm \
    redis-server \
    sudo \
    tree \
    vim \
    && rm -rf /var/lib/apt/lists/* \
    && sed -i '/en_US.UTF-8/s/^# //g' /etc/locale.gen \
    && locale-gen

# Create the developer user and set up permissions
RUN useradd -s /bin/bash -m developer && \
    usermod -aG sudo developer && \
    echo "developer ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

# Add claude code globally
RUN npm install -g @anthropic-ai/claude-code

# Install Language Servers (as root, globally available)
# Python LSP
RUN pip install --no-cache-dir pyright

# TypeScript/JavaScript LSP
RUN npm install -g @vtsls/language-server typescript

# Enable LSP tool for claude code
ENV ENABLE_LSP_TOOL=1

# Switch to developer user for remaining operations
USER developer

# Set up Python environment
ENV PATH=/home/developer/.local/bin:$PATH
WORKDIR /workspaces/simple_keystore

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

# Add git safe.directory for both volume and mounted paths
RUN git config --global --add safe.directory /workspaces/simple_keystore && \
    git config --global --add safe.directory /mounted/dev/simple_keystore

# Add alias for updating claude code
RUN echo "alias upc='sudo npm i -g @anthropic-ai/claude-code'" >> /home/developer/.bash_aliases
