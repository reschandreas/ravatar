#FROM rust:slim-bullseye as build
FROM rust:alpine as build

WORKDIR /build

RUN apk add --no-cache clang
#RUN apt-get -y update && apt-get -y install clang llvm

COPY Cargo.toml Cargo.lock /build/

RUN mkdir /build/src && echo "fn main() {}" > /build/src/main.rs

# cache dependencies
RUN cargo build --release

COPY src ./src

# make sure main.rs is rebuilt
RUN touch /build/src/main.rs
RUN cargo build --release

# Create a minimal docker image
FROM alpine:latest

#RUN apt-get update && apt-get install libc6

ENV RUST_LOG="error,ravatar=info"
COPY --from=build /build/target/release/ravatar /ravatar
ADD ./default /default
ENV RUST_BACKTRACE=full

EXPOSE 8080

VOLUME /raw
VOLUME /images
CMD ["/ravatar"]
ENTRYPOINT ["/ravatar"]