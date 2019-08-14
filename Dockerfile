FROM debian:buster as evmone_builder

RUN apt-get update -q && apt-get install -qy g++ cmake make

ADD . /src
RUN mkdir /build && cmake -S /src -B /build
RUN cmake --build /build --target install


FROM golang:1.12-buster as geth_builder
ARG geth_version=v1.9.2-evmc.6.3.0-0

RUN apt-get update -q && apt-get install -qy make git
RUN git clone --depth=1 --single-branch --branch=$geth_version https://github.com/ewasm/go-ethereum /go-ethereum
RUN cd /go-ethereum && make geth


FROM debian:buster

COPY --from=geth_builder /go-ethereum/build/bin/geth /usr/local/bin/
COPY --from=evmone_builder /usr/local/lib/libevmone.so /usr/local/lib/
RUN ldconfig

EXPOSE 8545 8546 30303 30303/udp
ENTRYPOINT ["geth"]
