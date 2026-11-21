FROM rust:1.98-slim
RUN rustup component add clippy
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client \
    && rm -rf /var/lib/apt/lists/*
