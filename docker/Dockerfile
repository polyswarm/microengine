FROM python:3.5
LABEL maintainer="PolySwarm Developers <info@polyswarm.io>"

WORKDIR /usr/src/app

COPY . .
RUN set -x && pip install --no-cache-dir -r requirements.txt

CMD ["microengine"]
