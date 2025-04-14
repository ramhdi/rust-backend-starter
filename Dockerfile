FROM rust:1.83-slim as builder

WORKDIR /app

# Create a dummy project to cache dependencies
RUN USER=root cargo new --bin dummy
WORKDIR /app/dummy
COPY Cargo.toml ./
RUN cargo build --release && \
    rm -rf src/ target/release/deps/rust_backend_starter* target/release/rust_backend_starter*

# Build the actual application
WORKDIR /app
COPY . .
# Copy the cached dependencies
RUN cp -r /app/dummy/target ./
# Build the application
RUN cargo build --release

# Use Google's distroless as runtime image
FROM gcr.io/distroless/cc-debian12

# Copy the binary and necessary files
COPY --from=builder /app/target/release/rust-backend-starter /usr/local/bin/app

# Set the working directory
WORKDIR /app

# Run as non-root user (distroless uses the nonroot (65532) user by default)
USER nonroot

# Expose the port the app will run on
EXPOSE 8080

# Command to run the application
CMD ["/usr/local/bin/app"]

