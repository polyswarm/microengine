FROM alpine:3.7
LABEL maintainer "PolySwarm Developers <info@polyswarm.io>, original YARA-alpine Dockerfile taken from https://github.com/blacktop"
ENV YARA_VERSION 3.7.1
ENV YARA_PY_VERSION 3.7.0

## INSTALL YARA DEPS, BUILD YARA
RUN apk add --no-cache openssl file jansson bison python python3 tini su-exec jq curl && python3 -m ensurepip &&\
pip3 install --upgrade pip setuptools && \
if [ ! -e /usr/bin/pip ]; then ln -s pip3 /usr/bin/pip ; fi && \
if [[ ! -e /usr/bin/python ]]; then ln -sf /usr/bin/python3 /usr/bin/python; fi
RUN apk add --no-cache -t .build-deps py-setuptools \
                                openssl-dev \
                                jansson-dev \
                                python-dev \
                                python3-dev \
                                build-base \
                                libc-dev \
                                file-dev \
                                automake \
                                autoconf \
                                libtool \
                                flex \
                                git \
  && set -x \
  && echo "Install Yara from source..." \
  && cd /tmp/ \
  && git clone --recursive --branch v$YARA_VERSION https://github.com/VirusTotal/yara.git \
  && cd /tmp/yara \
  && ./bootstrap.sh \
  && sync \
  && ./configure --with-crypto \
                 --enable-magic \
                 --enable-cuckoo \
                 --enable-dotnet \
  && make \
  && make install \
  && echo "Install yara-python..." \
  && cd /tmp/ \
  && git clone --recursive --branch v$YARA_PY_VERSION https://github.com/VirusTotal/yara-python \
  && cd yara-python \
  && python3 setup.py build --dynamic-linking \
  && python3 setup.py install \
  && echo "Make test_rule..." \
  && mkdir /rules \
  && echo "rule dummy { condition: true }" > /rules/test_rule \
  && rm -rf /tmp/*

## INSTALL DOCKERIZE
ENV DOCKERIZE_VERSION v0.6.1
RUN wget https://github.com/jwilder/dockerize/releases/download/$DOCKERIZE_VERSION/dockerize-alpine-linux-amd64-$DOCKERIZE_VERSION.tar.gz \
    && tar -C /usr/local/bin -xzvf dockerize-alpine-linux-amd64-$DOCKERIZE_VERSION.tar.gz \
    && rm dockerize-alpine-linux-amd64-$DOCKERIZE_VERSION.tar.gz

## COPY IN MICROENGINE FILES
WORKDIR /usr/src/app
COPY requirements.txt ./
RUN set -x && pip install --no-cache-dir -r requirements.txt
COPY . .
RUN  pip install .

## DONE
CMD ["microengine"]
