
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

# Build arguments for dynamic user configuration
ARG USER_ID=1000
ARG GROUP_ID=1000

# Install sudo
RUN apt-get update && apt-get install -y sudo && rm -rf /var/lib/apt/lists/*

# Create user with dynamic UID/GID first
RUN groupadd -g ${GROUP_ID} appuser && \
    useradd -u ${USER_ID} -g ${GROUP_ID} -m -s /bin/bash appuser && \
    echo "appuser ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Finally, Copy env first
COPY .env .

# Copy entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Create necessary directories and set ownership BEFORE switching to non-root user
RUN mkdir -p /data/downloads /data/working /app/logs /app/logs_cg4rs /app/analysis_results && \
    chown -R appuser:appuser /app /data

# Switch to non-root user
USER appuser



# Expose port
EXPOSE 8080

# Set entrypoint and default command
ENTRYPOINT ["/entrypoint.sh"]
CMD ["cvetracker4rs"]