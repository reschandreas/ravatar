# Ravatar

![build](https://github.com/reschandreas/ravatar/actions/workflows/build-and-push.yaml/badge.svg)
![tests](https://github.com/reschandreas/ravatar/actions/workflows/tests.yaml/badge.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![GitHub Release](https://img.shields.io/github/v/release/reschandreas/ravatar)

Ravatar is a simple implementation of the server specification of [Libavatar](https://wiki.libravatar.org/api/). The
project is written in Rust and used [surrogator](https://github.com/cweiske/surrogator)
by [cweiske](https://github.com/cweiske) as a reference.

## Usage

The server is simple and not designed to be used directly, but in a container, which is ready to use, or
k8s, thus it is not featuring any configuration via CLI, we only support environment variables.

#### Run locally

```shell
docker run -p 8080:8080 -v /path/to/images:/raw ghcr.io/reschandreas/ravatar:latest
```

### Environment Variables

| Variable                    | Description                                                                                                                                                                                                                                                          | Default   |
|-----------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------|
| `PATH_PREFIX`               | The path prefix of the server                                                                                                                                                                                                                                        | `/avatar` |
| `HOST`                      | The host of the server                                                                                                                                                                                                                                               | `0.0.0.0` |
| `PORT`                      | The port of the server                                                                                                                                                                                                                                               | `8080`    |
| `EXTENSION`                 | The extension of the images                                                                                                                                                                                                                                          | `png`     |
| `MM_EXTENSION`              | The extension of default and mm image                                                                                                                                                                                                                                | `png`     | 
| `RAW_PATH`                  | The path to the raw images                                                                                                                                                                                                                                           | `/raw`    |
| `IMAGES_PATH`               | The path to the generated images                                                                                                                                                                                                                                     | `/images` |
| `LOG_LEVEL`                 | The log level of the server                                                                                                                                                                                                                                          | `info`    |
| `OFFER_ORIGINAL_DIMENSIONS` | Offer the image with its original dimensions instead of resized to fill                                                                                                                                                                                              | `false`   |
| `OFFER_FACE_CENTERED_IMAGE` | Offer the image with the face in it centered, uses dlib for face recognition                                                                                                                                                                                         | `false`   |
| `OFFER_PORTRAIT_IMAGE`      | Offer the image squared if the lower part cut of if not squared                                                                                                                                                                                                      | `false`   |
| `DEFAULT_FORMAT`            | The default format of the image, "square", "original", "portrait", or "center"                                                                                                                                                                                       | `square`  | 
| `WATCH_DIRECTORIES`         | Whether or not to watch the specified directories                                                                                                                                                                                                                    | `true`    |  
| `SCAN_INTERVAL`             | If `WATCH_DIRECTORIES` is `false`, set it to a time (in minutes) you'd like the directories to be scanned. This has a double function as a periodic check even if `WATCH_DIRECTORIES` is `true`                                                                      | `60`      | 
| `STORAGE_ACCOUNT_URL`       | The URL of the Azure Blob Storage, if set, the application will connect to the Azure Storage Account, `RAW_PATH` is used as the container name for the source and `IMAGES_PATH` as the container name for the formatted images. `WATCH_DIRECTORIES` is set to false! |           |

If you want to serve an image with another identifier than the filename, i.e. the email address, you can use
LDAP to match the filename to other identifiers from your active directory. The configuration relies
on environment variables, which are prefixed with `LDAP_`.

| Variable                 | Description                                                                                          | Default                      | Example                       |
|--------------------------|------------------------------------------------------------------------------------------------------|------------------------------|-------------------------------|
| `LDAP_URL`               | The URL of the LDAP server                                                                           |                              | `ldap://localhost:389`        |
| `LDAP_BIND_USERNAME`     | The username for the LDAP server                                                                     | `cn=admin,dc=example,dc=com` |
| `LDAP_BIND_PASSWORD`     | The password for the LDAP server                                                                     | `admin`                      |
| `LDAP_BASE_DN`           | The base DN for the LDAP server                                                                      | `dc=example,dc=com`          |
| `LDAP_SEARCH_FILTER`     | The filter for the LDAP server, should filter the objectClass                                        |                              | `(objectClass=inetOrgPerson)` |
| `LDAP_INPUT_ATTRIBUTE`   | The attribute to search for in the LDAP server, corresponds to your filenames                        |                              | `sn`                          |
| `LDAP_TARGET_ATTRIBUTES` | The attributes to return from the LDAP server, which will then also serve the image. Separate by `,` |                              | `mail,username`               |
