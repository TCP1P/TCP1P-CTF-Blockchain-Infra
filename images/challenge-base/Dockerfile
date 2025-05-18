FROM ubuntu:24.04

# Install Python and other dependencies
RUN apt update && \
    apt install -y --no-install-recommends \
    python3 \
    python3-pip \
    tini \
    curl \
    build-essential && \
    rm -rf /var/lib/apt/lists/* && \
    useradd --shell /bin/bash -m ctf

COPY requirements.txt /root
RUN python3 -m pip install --no-cache-dir --default-timeout=9999 -r /root/requirements.txt --break-system-packages

RUN mkdir /var/log/ctf /startup

COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

ENTRYPOINT ["tini", "-g", "--"]
CMD ["bash", "/entrypoint.sh"]
