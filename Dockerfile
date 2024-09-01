FROM rust:1.67
LABEL authors="Madmegsox1"

ARG Port
ENV Port ${Port}

EXPOSE ${Port}/udp

WORKDIR /usr/src/netnoot
COPY . .

RUN cargo install --path .

RUN echo Port set to $Port

ENTRYPOINT netnoot -p $Port
