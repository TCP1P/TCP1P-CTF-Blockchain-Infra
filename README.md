# TCP1P CTF Blockchain Infra

This repository builds upon the original [paradigmxyz](https://github.com/paradigmxyz/paradigm-ctf-infrastructure/tree/master) infrastructure, adding a slick web interface and extra challenge setups. Think of it as your playground for exploring blockchain vulnerabilities in true CTF style.

## Docker Setup

### Build Images (or Pull from Docker Hub)
If you prefer pre-built containers, grab them directly from Docker Hub. Otherwise, to build your own Docker images:

```sh
cd ./images
./build.sh
```

### Launching Challenges
Each challenge runs via Docker Compose. For example, to run the Ethereum challenge:

```sh
cd ./challenge-eth
docker-compose up --build
```

Visit [http://127.0.0.1:48334/](http://127.0.0.1:48334/) in your browser. (Tip: The backend might take a few extra seconds to spin up.)

![Web Interface](image.png)

## Recommended Tools for Your Exploits

- **[Foundry](https://github.com/foundry-rs/foundry)** – A fast, flexible toolkit for Ethereum development.
- **[Foundpy](https://github.com/Wrth1/foundpy)** – Your Python sidekick for blockchain testing and automation.

## Our official docker hub

- https://hub.docker.com/r/dimasmaualana/solana
- https://hub.docker.com/r/dimasmaualana/eth
- https://hub.docker.com/r/dimasmaualana/cairo