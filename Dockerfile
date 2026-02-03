FROM golang:latest AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY ./anchor ./anchor
COPY ./cli ./cli
COPY ./logger ./logger
COPY ./proto ./proto
COPY ./service ./service
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o veilnet-conflux .


FROM ubuntu:latest
# systemd-resolved provides resolvectl (anchor uses it to set DNS for TUN)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    iptables \
    iproute2 \
    systemd-resolved \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /veilnet
COPY --from=builder /src/veilnet-conflux ./veilnet-conflux
RUN chmod +x ./veilnet-conflux

CMD ["./veilnet-conflux", "register", "-d"]
