FROM ubuntu:18.04 as builder

RUN apt-get update && \
    apt-get install -y libssl1.0-dev build-essential && \
    rm -rf /var/lib/apt/lists/* && \
    rm -rf /var/cache/apt/archives/*

WORKDIR /steward
COPY . .

WORKDIR /steward/src
RUN make

################################################################################

FROM ubuntu:18.04

WORKDIR /steward
COPY --from=builder /steward/bin /steward