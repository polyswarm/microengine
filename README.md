# Scratch

This project is a skeleton of a microengine. 

It cannot function due to a lack of an analysis backend, but it is capable of speaking to `polyswarmd`. 

When a file is bounty'ed, it simply prints an error that no analysis backend is available.

* scratch.go is a scratch microengine written in go. It has no analysis backend.

## Usage

First, launch polyswamrd:

```
$ ./scripts/compose.sh
```

Next, edit your microengine:

```
$ vi scratch.go
``

```
func scan(artifact string)(string, string, error){
    // you need to implement this
}
```

Then, run the microengine:

```
$ ./scripts/run_engine.sh
```
