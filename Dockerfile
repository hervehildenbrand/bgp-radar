# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy go mod files first for better layer caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build binary with optimizations
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o bgp-radar ./cmd/bgp-radar

# Runtime stage
FROM alpine:3.19

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

COPY --from=builder /app/bgp-radar /usr/local/bin/bgp-radar

# Default to rrc00 collector
ENV BGP_RADAR_COLLECTORS=rrc00

ENTRYPOINT ["bgp-radar"]
