# Helium Ubuntu Docker
This Dockerfile builds a container with clang and LLVM version 9 and a build of Helium.
Prebuilt image hosted on [Docker Hub](https://hub.docker.com/r/benjijang/helium),
available via `docker pull benjijang/helium`.

# To Build and Run

```
docker build -t benjijang/helium .
docker run -it benjijang/helium bash
```
