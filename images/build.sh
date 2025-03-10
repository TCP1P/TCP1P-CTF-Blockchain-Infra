#!/bin/bash

set -e

(cd challenge-base && docker build  . -t gcr.io/paradigmxyz/ctf/base:latest)
(cd challenge && docker build . -f Dockerfile.solana -t dimasmaualana/solana:latest)
(cd challenge && docker build . -f Dockerfile.cairo -t dimasmaualana/cairo:latest)
(cd challenge && docker build . -f Dockerfile.eth -t dimasmaualana/eth:latest)
