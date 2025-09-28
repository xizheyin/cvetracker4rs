
# Use official Rust image as base
FROM rust:1.75-bookworm

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    tar \
    rsync \
    ca-certificates \
    tzdata \
    libssl3 \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

RUN cargo --version

# Copy toolchain and dependency files first for better caching
COPY rust-toolchain.toml .
COPY Cargo.toml Cargo.lock ./
COPY callgraph4rs ./callgraph4rs/
COPY src/ ./src/



# Build dependencies only
WORKDIR /app/callgraph4rs
RUN cargo build --release --bins
# Install callgraph4rs binaries
RUN cp target/release/cg4rs /usr/local/bin/
RUN cp target/release/cargo-cg4rs /usr/local/bin/
RUN cp target/release/call-cg4rs /usr/local/bin/

WORKDIR /app
RUN cargo build --release --bins
# Install main project binaries
RUN cp target/release/cvetracker4rs /usr/local/bin/
RUN cp target/release/run_from_csv /usr/local/bin/
RUN cp target/release/stats /usr/local/bin/

# Finally, Copy env
COPY .env .

# Create necessary directories
RUN mkdir -p /data/downloads /data/working /app/logs /app/analysis_results

# Expose port
EXPOSE 8080

# Set default command
CMD ["cvetracker4rs"]