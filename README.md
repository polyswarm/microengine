# Scratch

This project is a skeleton of a microengine. 

It cannot function due to a lack of an analysis backend, but it is capable of speaking to `polyswarmd`. 

When a file is bounty'ed, it simply prints an error that no analysis backend is available.

* scratch.go is a scratch microengine written in go. It has no analysis backend.

* scratch.py is a scratch microengine written in python. It has no analysis backend.

## Usage

### scratch.py

#### Required

```
python >= 3.4
pip >= 10.x
```

#### Setup

```
$ (sudo) pip3.6 install pathlib
$ (sudo) pip3.6 install websockets
```

#### Execution

Then, 

```
$ python3.6 scratch.py
```

## Failures

### websocket requires Python >= 3.4

```
Exception: websockets requires Python >= 3.4.`
```

```
$ curl -O https://bootstrap.pypa.io/get-pip.py
$ sudo python3.6 get-pip.py
```
