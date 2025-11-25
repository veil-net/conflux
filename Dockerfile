FROM ubuntu:latest

# Update package list and install dependencies in a single layer
RUN apt-get update && apt-get install -y --no-install-recommends \
    iptables \
    iproute2 \
    ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /tmp/* /var/tmp/*

# Set working directory
WORKDIR /veilnet

# Copy the binary
COPY ./veilnet-conflux ./veilnet-conflux

# Set proper permissions
RUN chmod +x ./veilnet-conflux

# Use exec form for CMD
CMD ["./veilnet-conflux"]