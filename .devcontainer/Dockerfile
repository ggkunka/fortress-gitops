# Use Microsoft's devcontainer base image with Python 3.11
FROM mcr.microsoft.com/devcontainers/python:1-3.11

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
        postgresql-client \
        redis-tools \
        net-tools \
        software-properties-common \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Kind (Kubernetes in Docker)
RUN curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.20.0/kind-linux-amd64 \
    && chmod +x ./kind \
    && mv ./kind /usr/local/bin/kind

# Install Buildah using more reliable method
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends \
        podman \
        buildah \
        skopeo \
        fuse-overlayfs \
        slirp4netns \
        uidmap \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    || { \
        echo "Ubuntu repos failed, trying alternative installation..."; \
        curl -fsSL https://download.opensuse.org/repositories/devel:kubic:libcontainers:stable/xUbuntu_$(lsb_release -rs)/Release.key | gpg --dearmor | tee /etc/apt/keyrings/devel_kubic_libcontainers_stable.gpg > /dev/null; \
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/devel_kubic_libcontainers_stable.gpg] https://download.opensuse.org/repositories/devel:kubic:libcontainers:stable/xUbuntu_$(lsb_release -rs)/ /" | tee /etc/apt/sources.list.d/devel:kubic:libcontainers:stable.list > /dev/null; \
        apt-get update; \
        apt-get -y install buildah podman skopeo; \
        apt-get clean; \
        rm -rf /var/lib/apt/lists/*; \
    }

# Configure containers for rootless mode
RUN echo 'vscode:100000:65536' >> /etc/subuid \
    && echo 'vscode:100000:65536' >> /etc/subgid \
    && mkdir -p /home/vscode/.config/containers \
    && echo 'unqualified-search-registries = ["docker.io"]' > /home/vscode/.config/containers/registries.conf \
    && echo '[storage]' > /home/vscode/.config/containers/storage.conf \
    && echo 'driver = "vfs"' >> /home/vscode/.config/containers/storage.conf \
    && chown -R vscode:vscode /home/vscode/.config

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
        fastapi \
        pandas \
        matplotlib \
        seaborn \
        plotly \
        jupyter \
        ipywidgets \
        structlog

# Set up shell environment
RUN echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc \
    && echo 'alias k=kubectl' >> ~/.bashrc \
    && echo 'alias ll="ls -la"' >> ~/.bashrc \
    && echo 'source <(kubectl completion bash)' >> ~/.bashrc \
    && echo 'alias mcp-demo="make poc-demo"' >> ~/.bashrc \
    && echo 'alias mcp-test="make test"' >> ~/.bashrc \
    && echo 'alias mcp-status="make services-status"' >> ~/.bashrc \
    && echo 'export BUILDAH_ISOLATION=chroot' >> ~/.bashrc \
    && echo 'export BUILDAH_FORMAT=docker' >> ~/.bashrc \
    && echo 'export STORAGE_DRIVER=vfs' >> ~/.bashrc

WORKDIR /workspace