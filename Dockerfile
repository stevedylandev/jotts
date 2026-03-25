FROM rust:1-slim-bookworm AS builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
COPY --from=builder /app/target/release/jotts /usr/local/bin/jotts
WORKDIR /data
EXPOSE 3000
ENV HOST=0.0.0.0
ENV PORT=3000
CMD ["jotts"]
