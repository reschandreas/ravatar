FROM rust:alpine AS build-prep
ARG featureflag
WORKDIR /build

RUN apk add --no-cache clang gcompat build-base musl-dev openssl-dev openldap-dev cmake libpng-dev g++ lapack-dev
RUN mkdir /build/src && echo "fn main() {}" > /build/src/main.rs
ENV PKG_CONFIG_PATH="/usr/lib/pkgconfig" \
    LD_LIBRARY_PATH=/usr/lib:/usr/local/lib \
    OPENSSL_DIR="/usr"

FROM build-prep AS build

COPY Cargo.toml Cargo.lock /build/

# because we are not guaranteed to use the same version of alpine, we need to statically link the libraries
ENV RUSTFLAGS="-Ctarget-feature=-crt-static"

# cache dependencies
RUN cargo build --release

COPY src ./src

# make sure main.rs is rebuilt
RUN touch /build/src/main.rs
RUN cargo build --release $featureflag

# Create a minimal docker image
FROM alpine:latest

RUN apk add --no-cache gcompat libgcc lapack libstdc++

ENV RUST_LOG="debug,ravatar=info"

COPY --from=build /build/target/release/ravatar /ravatar
ADD ./default /default

EXPOSE 8080

VOLUME /raw
VOLUME /images

ENTRYPOINT ["/ravatar"]