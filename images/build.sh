#!/bin/bash

set -e

(cd challenge-base && docker build  . -t gcr.io/paradigmxyz/ctf/base:latest)
echo "building cairo"
(cd challenge && docker build . -f Dockerfile.cairo -t dimasmaualana/cairo:latest)
echo "building eth"
(cd challenge && docker build . -f Dockerfile.eth -t dimasmaualana/eth:latest)
echo "building solana"
(cd challenge && docker build . -f Dockerfile.solana -t dimasmaualana/solana:latest)
