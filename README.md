# Ravatar

![build](https://github.com/reschandreas/ravatar/actions/workflows/build-and-push.yaml/badge.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

Ravatar is a simple implementation of the server specification of [Libavatar](https://wiki.libravatar.org/api/). The 
project is written in Rust and used [surrogator](https://github.com/cweiske/surrogator) by cweiske as a reference.

## Usage

The server is very simple to use and not designed to be used in a container, which is ready to use, or k8s, thus it is not featuring any configuration
via CLI, we only support environment variables.

#### Run locally

```shell
docker run -p 8080:8080 -v /path/to/images:/raw ghcr.io/reschandreas/ravatar:images
```

### Environment Variables

| Variable | Description                 | Default |
|----------|-----------------------------|--------|
| `PATH_PREFIX` | The path prefix of the server | `/avatar` |
| `HOST` | The host of the server      | `0.0.0.0` |
| `PORT` | The port of the server      | `8080` |
| `EXTENSION` | The extension of the images | `png` |
| `RAW_PATH` | The path to the raw images  | `/raw` |
| `IMAGES_PATH` | The path to the generated images | `/images` |
| `LOG_LEVEL` | The log level of the server | `info` |
