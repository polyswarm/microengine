FROM golang:1.10-alpine as builder
LABEL maintainer="PolySwarm Developers <info@polyswarm.io>"

RUN apk add --no-cache alpine-sdk git bash
COPY . .

# RUN env GIT_TERMINAL_PROMPT=1 go get github.com/ethereum/go-etheruem
RUN ./scripts/import.sh
