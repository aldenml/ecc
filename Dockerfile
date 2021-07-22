FROM ubuntu:20.04

ENV DEBIAN_FRONTEND noninteractive
RUN apt update -y \
    && apt install -y \
    wget unzip less \
    python perl make cmake \
    g++ ninja-build git
