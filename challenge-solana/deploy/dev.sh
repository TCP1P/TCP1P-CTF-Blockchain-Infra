#!/bin/bash

export BLOCKCHAIN_TYPE=solana
export FLAG=PCTF{placeholder}
export DISABLE_TICKET=true

rm /tmp/solana_state.pickle
ln -s ../setup/ .
# Start port forwarding in background
socat TCP-LISTEN:8547,fork TCP:localhost:8546 & gunicorn --bind 0.0.0.0:8546 -w 4 chal:app