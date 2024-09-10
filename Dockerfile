FROM rust:latest AS builder

# Install build dependencies
RUN apt-get -y update && \
    apt-get install -y  \
    clang\
    libudev-dev\
    \
    && \
    apt-get autoremove -y; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/*

ENV HOME=/home/root
WORKDIR $HOME/app

COPY Cargo.lock Cargo.toml ./
COPY . .

RUN cp -r /usr/local/rustup /rustup
RUN --mount=type=cache,target=/usr/local/rustup cp -r /rustup /usr/local && rm -r /rustup
RUN cp -r /usr/local/cargo /cargo
RUN --mount=type=cache,target=/usr/local/cargo cp -r /cargo /usr/local && rm -r /cargo

RUN --mount=type=cache,target=/usr/local/rustup \
    --mount=type=cache,target=/usr/local/cargo \
    --mount=type=cache,target=$HOME/app/target \
    cargo build --release && cp $HOME/app/target/release/orchestrator ./orchestrator

FROM debian:bookworm

RUN apt-get -y update && \
    apt-get install -y openssl ca-certificates tini &&\
    apt-get autoremove -y; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder home/root/app/orchestrator ./

CMD ["/app/orchestrator"]
