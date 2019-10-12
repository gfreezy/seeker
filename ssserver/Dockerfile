FROM ubuntu:latest

WORKDIR /opt
RUN apt-get update && \
    apt-get install -y wget xz-utils && \
    cd /opt && \
    wget https://github.com/shadowsocks/shadowsocks-rust/releases/download/v1.7.2/shadowsocks-v1.7.2-stable.x86_64-unknown-linux-musl.tar.xz && \
    tar xJf shadowsocks-v1.7.2-stable.x86_64-unknown-linux-musl.tar.xz

CMD ./ssserver
