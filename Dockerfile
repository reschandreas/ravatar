FROM rust:alpine AS build-prep

WORKDIR /build

RUN apk add --no-cache clang gcompat build-base musl-dev openssl-dev openldap-dev
RUN apk add --no-cache cmake openblas-dev libpng-dev blas-dev g++ gfortran libgfortran lapack-dev
RUN mkdir /build/src && echo "fn main() {}" > /build/src/main.rs
ENV PKG_CONFIG_PATH="/usr/lib/pkgconfig" \
    LD_LIBRARY_PATH=/usr/lib:/usr/local/lib \
    OPENSSL_DIR="/usr"

FROM build-prep AS build

COPY Cargo.toml Cargo.lock /build/

# because we are not guaranteed to use the same version of alpine, we need to statically link the libraries
ENV RUSTFLAGS="-Ctarget-feature=-crt-static"

ENV RUST_BACKTRACE=1
# cache dependencies
RUN #cargo build --release

COPY src ./src

# make sure main.rs is rebuilt
RUN touch /build/src/main.rs
#RUN cargo build --release
#
## Create a minimal docker image
#FROM alpine:latest
#
#RUN apk add --no-cache gcompat libgcc
#
#ENV RUST_LOG="debug,ravatar=info"
#
#COPY --from=build /build/target/release/ravatar /ravatar
#ADD ./default /default
#ENV RUST_BACKTRACE=full
#
#EXPOSE 8080
#
#VOLUME /raw
#VOLUME /images
#
#ENTRYPOINT ["/ravatar"]