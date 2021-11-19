FROM builder:latest as builder

# This COPY is limited by .dockerignore
COPY ./ /gadget
RUN cd /gadget/gadget-container && make gadget-container-deps

# Builder: traceloop

# traceloop built from:
# https://github.com/kinvolk/traceloop/commit/95857527df8d343a054d3754dc3b77c7c8c274c7
# See:
# - https://github.com/kinvolk/traceloop/actions
# - https://hub.docker.com/r/kinvolk/traceloop/tags

FROM docker.io/kinvolk/traceloop:20211109004128958575 as traceloop

# Main gadget image

# BCC built from the gadget branch in the kinvolk/bcc fork:
# https://github.com/kinvolk/bcc/commit/a81b62e2d04fbebfbbd75787a735edede4555cf8
# See BCC section in docs/CONTRIBUTING.md for further details.

FROM quay.io/kinvolk/bcc:a81b62e2d04fbebfbbd75787a735edede4555cf8-focal-release

RUN set -ex; \
	export DEBIAN_FRONTEND=noninteractive; \
	apt-get update && \
	apt-get install -y --no-install-recommends \
		ca-certificates curl jq wget xz-utils binutils && \
		rmdir /usr/src && ln -sf /host/usr/src /usr/src

COPY gadget-container/entrypoint.sh gadget-container/cleanup.sh /

COPY --from=builder /gadget/gadget-container/bin/gadgettracermanager /bin/
COPY --from=builder /gadget/gadget-container/bin/networkpolicyadvisor /bin/

COPY gadget-container/gadgets/bcck8s /opt/bcck8s/

COPY --from=traceloop /bin/traceloop /bin/

## Hooks Begins

# OCI
COPY gadget-container/hooks/oci/prestart.sh gadget-container/hooks/oci/poststop.sh /opt/hooks/oci/
COPY --from=builder /gadget/gadget-container/bin/ocihookgadget /opt/hooks/oci/

# cri-o
COPY gadget-container/hooks/crio/gadget-prestart.json gadget-container/hooks/crio/gadget-poststop.json /opt/hooks/crio/

# nri
COPY --from=builder /gadget/gadget-container/bin/nrigadget /opt/hooks/nri/
COPY gadget-container/hooks/nri/conf.json /opt/hooks/nri/

## Hooks Ends
