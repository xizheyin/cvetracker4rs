
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

# Copy project files (excluding files listed in .dockerignore)
COPY . .

# Build callgraph4rs first (since main project depends on it)
WORKDIR /app/callgraph4rs
RUN cargo build --release

# Install callgraph4rs binaries
RUN cp target/release/cg4rs /usr/local/bin/
RUN cp target/release/cargo-cg4rs /usr/local/bin/
RUN cp target/release/call-cg4rs /usr/local/bin/

# Build main project
WORKDIR /app
RUN cargo build --release

# Install main project binaries
RUN cp target/release/cvetracker4rs /usr/local/bin/
RUN cp target/release/run_from_csv /usr/local/bin/
RUN cp target/release/stats /usr/local/bin/

# Set environment variables
ENV RUST_LOG=info
ENV RUST_BACKTRACE=1

# Create necessary directories
RUN mkdir -p /data/downloads /data/working /app/logs /app/analysis_results

# Expose port
EXPOSE 8080

# Set default command
CMD ["cvetracker4rs"]