# Docker

```sh
docker build -t polyswarm/microengine -f docker/Dockerfile .
```
For use with `polyswarm/orchestration/tutorial[,1,2].yml`
# SECURITY WARNING

`microengine` implicitly trusts transaction signing requests from `polyswarmd`.
A malicious instance of `polyswarmd` or an attacker with sufficient network capabilities may abuse this trust relationship to cause `microengine` to transfer all NCT, ETH or other tokens to an attacker address.

Therefore: 
1. **ONLY CONNECT `microengine` TO `polyswarmd` INSTANCES THAT YOU TRUST**
2. **DO NOT ALLOW `microengine` <-> `polyswarmd` COMMUNICATIONS TO TRAVERSE AN UNTRUSTED NETWORK LINK**

In other words, only run `microengine` on a co-located `localhost` with `polyswarmd`.

This is a temporarily limitation - `microengine`'s trust in `polyswarmd` will be eliminated in the near future.
