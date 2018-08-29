#!/bin/bash
./scripts/wait_for_it.sh $POLYSWARMD_HOST:$POLYSWARMD_PORT -t 0
./scripts/wait_for_it.sh $API_KEY_HOST -t 0

export API_KEY=$(./scripts/get_api_key.sh)

echo "microengine API key: ${API_KEY}"

microengine $*
