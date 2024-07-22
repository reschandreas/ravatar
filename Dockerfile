#FROM rust:slim-bullseye as build
FROM rust:alpine AS build-prep

WORKDIR /build

RUN apk add --no-cache clang gcompat build-base musl-dev openssl-dev openldap-dev
RUN mkdir /build/src && echo "fn main() {}" > /build/src/main.rs
ENV PKG_CONFIG_PATH="/usr/lib/pkgconfig"
ENV OPENSSL_DIR="/usr"

FROM build-prep AS build

COPY Cargo.toml Cargo.lock /build/

# cache dependencies
RUN cargo build --release

COPY src ./src

# make sure main.rs is rebuilt
RUN touch /build/src/main.rs
RUN cargo build --release

# Create a minimal docker image
FROM alpine:latest

#RUN apk add --no-cache clang gcompat build-base musl-dev openssl-dev openldap-dev openldap openssl
RUN apk add --no-cache gcompat musl-dev
ENV RUST_LOG="debug,ravatar=info"
ENV OPENSSL_DIR="/usr"
COPY --from=build /build/target/release/ravatar /ravatar
ADD ./default /default
ENV RUST_BACKTRACE=full

EXPOSE 8080

VOLUME /raw
VOLUME /images

CMD ["/ravatar"]
ENTRYPOINT ["/ravatar"]