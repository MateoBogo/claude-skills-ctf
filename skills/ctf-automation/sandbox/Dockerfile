# ctf-automation sandbox image
# Built with: docker build -t ctf-sandbox /home/ubuntu/.claude/skills/ctf-automation/sandbox
# Used by   : sandbox.sh run|attach|shell|qemu-kernel
#
# Philosophy: everything a CTF pwn/rev/crypto worker needs, pinned so that
# exploit_loop.py produces reproducible crash dumps.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_BREAK_SYSTEM_PACKAGES=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential gcc-multilib g++-multilib \
    python3 python3-pip python3-dev python3-venv \
    git curl wget ca-certificates jq file xxd vim-tiny less procps psmisc \
    gdb gdb-multiarch \
    binutils binutils-multiarch \
    elfutils readelf \
    patchelf \
    strace ltrace \
    qemu-user qemu-user-static qemu-system-x86 qemu-system-arm qemu-system-aarch64 \
    socat netcat-openbsd \
    libc6-dbg libc6-dbg:i386 || true && \
    apt-get install -y --no-install-recommends checksec radare2 && \
    rm -rf /var/lib/apt/lists/*

# pwntools + common python exploit deps
RUN pip3 install --no-cache-dir \
    pwntools==4.13.1 \
    ropper==1.13.12 \
    angr==9.2.115 \
    capstone==5.0.3 \
    unicorn==2.1.1 \
    frida-tools==12.5.0 \
    qiling==1.4.6 \
    pycryptodome==3.20.0 \
    sympy==1.12 \
    z3-solver==4.13.0 \
    cryptography==42.0.5 \
    pyelftools==0.31 \
    requests==2.32.3

# ROPgadget + one_gadget + seccomp-tools
RUN pip3 install --no-cache-dir ROPgadget==7.5 && \
    gem install --no-document one_gadget seccomp-tools 2>/dev/null || \
    apt-get update && apt-get install -y --no-install-recommends ruby ruby-dev && \
    gem install --no-document one_gadget seccomp-tools && \
    rm -rf /var/lib/apt/lists/*

# pwndbg (fallback to GEF if pwndbg install fails)
RUN git clone --depth 1 https://github.com/pwndbg/pwndbg /opt/pwndbg && \
    cd /opt/pwndbg && ./setup.sh 2>/dev/null || \
    (rm -rf /opt/pwndbg && \
     wget -qO- https://gef.blah.cat/sh | sh) || true

# libc-database (shallow — full clone is multi-GB; we snapshot the index only)
RUN mkdir -p /opt/libc-database && \
    git clone --depth 1 https://github.com/niklasb/libc-database /opt/libc-database && \
    cd /opt/libc-database && ./get ubuntu 2>/dev/null || true

# Ghidra headless (analyzeHeadless) — optional; comment out to slim image
RUN apt-get update && apt-get install -y --no-install-recommends openjdk-21-jdk-headless unzip && \
    wget -q https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.2.1_build/ghidra_11.2.1_PUBLIC_20241105.zip -O /tmp/ghidra.zip && \
    unzip -q /tmp/ghidra.zip -d /opt && \
    ln -s /opt/ghidra_11.2.1_PUBLIC/support/analyzeHeadless /usr/local/bin/ghidra-headless && \
    rm /tmp/ghidra.zip && \
    rm -rf /var/lib/apt/lists/*

# SageMath — large; install only if SAGE=1 build arg set
ARG SAGE=0
RUN if [ "$SAGE" = "1" ]; then \
      apt-get update && apt-get install -y --no-install-recommends sagemath && \
      rm -rf /var/lib/apt/lists/* ; \
    fi

WORKDIR /work
CMD ["/bin/bash"]
