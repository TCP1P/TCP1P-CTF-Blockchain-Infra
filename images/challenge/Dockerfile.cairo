FROM shardlabs/starknet-devnet-rs:0.2.4 AS starknet
FROM gcr.io/paradigmxyz/ctf/base:latest

COPY --from=starknet /usr/local/bin/starknet-devnet /bin/starknet-devnet

USER root
ENV SHELL=/bin/bash
RUN curl --proto '=https' --tlsv1.2 -sSf https://docs.swmansion.com/scarb/install.sh | sh -s -- -v 2.8.0

COPY 96-start-launcher /startup

COPY src/sandbox /usr/lib/python/sandbox

ENV PYTHONPATH=/usr/lib/python

ENV BLOCKCHAIN_TYPE=cairo
