#!/bin/bash

if [ -z "$1" ]; then
  echo "Usage: $0 <version>"
  exit 1
fi

VERSION=$1

for IMAGE in cairo eth solana; do
  sudo docker tag dimasmaualana/$IMAGE:latest dimasmaualana/$IMAGE:$VERSION
  sudo docker push dimasmaualana/$IMAGE:$VERSION
  sudo docker push dimasmaualana/$IMAGE:latest
  echo "Pushed dimasmaualana/$IMAGE:latest and :$VERSION"
done
