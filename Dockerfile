FROM rust:1.45.0 AS build

WORKDIR /usr/src

RUN rustup target add x86_64-unknown-linux-musl

RUN USER=root cargo new --bin rust_packetdump

WORKDIR /usr/src/rust_packetdump

COPY Cargo.toml Cargo.lock ./

RUN cargo build --release

COPY src ./src

RUN cargo install --target x86_64-unknown-linux-musl --path .

FROM scratch

COPY --from=build /usr/local/cargo/bin/rust_packetdump .

USER 0

CMD ["./rust_packetdump", "wlp1s0"]
