# Use Ubuntu as base image
FROM mcr.microsoft.com/devcontainers/base:ubuntu

# Avoid prompts from apt
ENV DEBIAN_FRONTEND=noninteractive

# Update and install base tools
RUN apt-get update && apt-get install -y \
    # Build essentials
    build-essential \
    cmake \
    git \
    curl \
    wget \
    unzip \
    python3 \
    python3-pip \
    python3-dev \
    # Network analysis tools
    nmap \
    tcpdump \
    wireshark \
    tshark \
    netcat-openbsd \
    socat \
    dnsutils \
    # Web testing tools
    dirb \
    nikto \
    sqlmap \
    hydra \
    # Reverse engineering tools
    gdb \
    gdb-multiarch \
    radare2 \
    binutils \
    strace \
    ltrace \
    file \
    hexedit \
    # Cryptography tools
    hashcat \
    john \
    openssl \
    # Forensics tools
    binwalk \
    foremost \
    steghide \
    exiftool \
    # Additional utilities
    jq \
    tmux \
    vim \
    nano \
    tree \
    zip \
    p7zip-full \
    && rm -rf /var/lib/apt/lists/*

# Install gobuster via Go (not available in apt for Ubuntu)
RUN apt-get update && apt-get install -y golang-go && \
    go install github.com/OJ/gobuster/v3@latest && \
    ln -s /root/go/bin/gobuster /usr/local/bin/gobuster && \
    rm -rf /var/lib/apt/lists/*

# Install pwndbg for GDB
RUN cd /opt && \
    git clone https://github.com/pwndbg/pwndbg && \
    cd pwndbg && \
    ./setup.sh

# Install Python security tools (using --break-system-packages for Docker environment)
RUN pip3 install --no-cache-dir --break-system-packages \
    pwntools \
    ropper \
    capstone \
    keystone-engine \
    unicorn \
    z3-solver \
    requests \
    beautifulsoup4 \
    pycryptodome \
    scapy \
    angr \
    r2pipe \
    volatility3

# Install ROPgadget
RUN pip3 install --no-cache-dir --break-system-packages ROPgadget

# Download and install Ghidra
RUN wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.2.1_build/ghidra_11.2.1_PUBLIC_20241105.zip -O /tmp/ghidra.zip && \
    unzip /tmp/ghidra.zip -d /opt/ && \
    rm /tmp/ghidra.zip && \
    ln -s /opt/ghidra_11.2.1_PUBLIC /opt/ghidra

# Add Ghidra to PATH
ENV PATH="/opt/ghidra:${PATH}"

# Clean up unnecessary files
RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Install Burp Suite Community (headless, for scripting)
# Note: Full GUI version requires X11 forwarding
RUN wget "https://portswigger-cdn.net/burp/releases/download?product=community&version=2024.10.1&type=Jar" -O /opt/burpsuite_community.jar || echo "Burp download may need manual intervention"

# Install ZAP (OWASP ZAP)
RUN wget https://github.com/zaproxy/zaproxy/releases/download/v2.15.0/ZAP_2.15.0_Linux.tar.gz -O /tmp/zap.tar.gz && \
    tar -xzf /tmp/zap.tar.gz -C /opt/ && \
    rm /tmp/zap.tar.gz && \
    ln -s /opt/ZAP_2.15.0 /opt/zap

ENV PATH="/opt/zap:${PATH}"

# Create workspace directory
RUN mkdir -p /workspace

# Set working directory
WORKDIR /workspace

# Reset DEBIAN_FRONTEND
ENV DEBIAN_FRONTEND=dialog

# Create a welcome message
RUN echo '#!/bin/bash\n\
echo "==========================================="\n\
echo "  CTF Hacking Environment Ready!"\n\
echo "==========================================="\n\
echo ""\n\
echo "Available Tools:"\n\
echo "  Network: nmap, wireshark, tcpdump"\n\
echo "  Web: gobuster, nikto, sqlmap, hydra"\n\
echo "  Reverse: ghidra, radare2, gdb+pwndbg"\n\
echo "  Crypto: hashcat, john, openssl"\n\
echo "  Forensics: binwalk, foremost, volatility"\n\
echo "  Python: pwntools, angr, z3, requests"\n\
echo ""\n\
echo "Happy Hacking!"\n\
echo "==========================================="\n' > /usr/local/bin/welcome.sh && \
    chmod +x /usr/local/bin/welcome.sh

CMD ["/bin/bash"]
