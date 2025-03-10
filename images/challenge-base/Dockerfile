# Build stage
FROM python:3.12-slim as builder

RUN apt update && \
    apt install -y --no-install-recommends \
    git \
    gcc \
    cmake \
    make \
    g++ \
    libgmp3-dev \
    libboost-all-dev && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt /root
RUN python3 -m pip install --no-cache-dir --default-timeout=9999 -r /root/requirements.txt

# Final stage
FROM python:3.12-slim

RUN mkdir /var/log/ctf /startup && \
    apt update && \
    apt install -y --no-install-recommends tini curl build-essential libc6 && \
    rm -rf /var/lib/apt/lists/* && \
    useradd --shell /bin/bash -m ctf

COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

ENTRYPOINT ["tini", "-g", "--"]
CMD ["bash", "/entrypoint.sh"]
