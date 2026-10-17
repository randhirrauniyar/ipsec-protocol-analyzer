FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    strongswan \
    strongswan-swanctl \
    libstrongswan-standard-plugins \
    libstrongswan-extra-plugins \
    tcpdump \
    iproute2 \
    iputils-ping \
    iperf3 \
    procps \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /captures /etc/swanctl/conf.d

CMD ["sh", "-c", "/usr/lib/ipsec/starter --nofork & sleep 2 && swanctl --load-all && tail -f /dev/null"]
