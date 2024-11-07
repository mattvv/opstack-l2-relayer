FROM rust:latest

WORKDIR /usr/src/app

# Copy the application code
COPY . .

# Build the application
RUN cargo build --release

# Run the application
CMD ["./target/release/app"]
