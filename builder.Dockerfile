# Prepare and build gadget artifacts in a container
ARG OS_TAG=20.04
FROM ubuntu:${OS_TAG} as builder

RUN set -ex; \
	export DEBIAN_FRONTEND=noninteractive; \
	apt-get update && \
	apt-get install -y gcc make golang-1.16 ca-certificates git clang \
		software-properties-common libseccomp-dev && \
	add-apt-repository -y ppa:tuxinvader/kernel-build-tools && \
	apt-get update && \
	apt-get install -y libbpf-dev && \
	ln -s /usr/lib/go-1.16/bin/go /bin/go

# Cache go modules so they won't be downloaded at each build
COPY go.mod go.sum /gadget/
RUN cd /gadget && go mod download
