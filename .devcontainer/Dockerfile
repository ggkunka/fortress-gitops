# Use Microsoft's devcontainer base image
FROM mcr.microsoft.com/devcontainers/python:3.11

# Install system dependencies
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends \
        curl \
        wget \
        git \
        vim \
        jq \
        unzip \
        ca-certificates \
        gnupg \
        lsb-release \
        build-essential \
        libpq-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Kind (Kubernetes in Docker)
RUN curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.20.0/kind-linux-amd64 \
    && chmod +x ./kind \
    && mv ./kind /usr/local/bin/kind

# Install Buildah
RUN echo "deb http://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/xUbuntu_$(lsb_release -rs)/ /" > /etc/apt/sources.list.d/devel:kubic:libcontainers:stable.list \
    && curl -L "https://download.opensuse.org/repositories/devel:kubic:libcontainers:stable/xUbuntu_$(lsb_release -rs)/Release.key" | apt-key add - \
    && apt-get update \
    && apt-get -y install buildah \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install additional tools
RUN curl -fsSL https://get.docker.com | sh \
    && usermod -aG docker vscode

# Install yq for YAML processing
RUN wget -qO /usr/local/bin/yq https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64 \
    && chmod +x /usr/local/bin/yq

# Create workspace directory
RUN mkdir -p /workspace && chown vscode:vscode /workspace

# Switch to vscode user
USER vscode

# Install Python tools
RUN pip install --user --upgrade pip \
    && pip install --user \
        pytest \
        pytest-cov \
        pytest-asyncio \
        black \
        isort \
        pylint \
        mypy \
        httpx \
        uvicorn \
        fastapi

# Set up shell environment
RUN echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc \
    && echo 'alias k=kubectl' >> ~/.bashrc \
    && echo 'alias ll="ls -la"' >> ~/.bashrc \
    && echo 'source <(kubectl completion bash)' >> ~/.bashrc

WORKDIR /workspace