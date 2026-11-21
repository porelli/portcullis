# ghcr.io/porelli/portcullis-snr: medik8s Self Node Remediation v0.13.0
# (the pinned upstream tag, commit 79fb7928…) with Portcullis' one patch
# (0001-secret-cache-own-namespace.patch: its Secret cache holds only its
# peers' certificate in its own namespace, never every namespace's
# Secrets, and the agent's pod cache only its own namespace; plan Task 24
# fix rounds 1–2, user ruling "Patch SNR, drop NHC"). The Go build runs on
# the build platform and cross-compiles (GOARCH=$TARGETARCH: no emulated
# compile for arm64); apk packages are pinned to the versions of the pinned
# alpine 3.24.3 (a rebuild with a newer revision fails, never drifts).
# Built and cosign-signed by .github/workflows/snr.yml; the labels record
# the upstream tag, commit and the patch's sha256.
# golang:1.27.3-alpine3.24
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.27.3-alpine3.24@sha256:fa4881266890ef051f0ce63afdfaccb69bbe8186084387f4fafd60d7ecbabc71 AS builder
ARG TARGETARCH
ARG SNR_TAG=v0.13.0
ARG SNR_COMMIT=79fb792830c6db78b0dab45c45f5b79591118c76
ARG PATCH_SHA256=17d5d68ff70b9254381d6a31093f560c9427ab2b876fe9c28dd3e308cb7a14d9
RUN apk add --no-cache git=2.54.1-r0
WORKDIR /src
RUN git clone --depth 1 --branch "$SNR_TAG" https://github.com/medik8s/self-node-remediation.git . \
 && test "$(git rev-parse HEAD)" = "$SNR_COMMIT"
COPY 0001-secret-cache-own-namespace.patch /tmp/
RUN echo "$PATCH_SHA256  /tmp/0001-secret-cache-own-namespace.patch" | sha256sum -c - \
 && git apply --check /tmp/0001-secret-cache-own-namespace.patch && git apply /tmp/0001-secret-cache-own-namespace.patch
ENV GOTOOLCHAIN=local CGO_ENABLED=0
RUN GOARCH="$TARGETARCH" go build -mod=vendor -trimpath \
      -ldflags "-s -w -X github.com/medik8s/self-node-remediation/version.Version=${SNR_TAG}-portcullis1 -X github.com/medik8s/self-node-remediation/version.GitCommit=${SNR_COMMIT}" \
      -o /manager ./cmd

# alpine:3.24.3
FROM docker.io/library/alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
ARG SNR_TAG=v0.13.0
ARG SNR_COMMIT=79fb792830c6db78b0dab45c45f5b79591118c76
ARG PATCH_SHA256=17d5d68ff70b9254381d6a31093f560c9427ab2b876fe9c28dd3e308cb7a14d9
LABEL io.portcullis.snr.upstream="https://github.com/medik8s/self-node-remediation" \
      io.portcullis.snr.upstream-tag="${SNR_TAG}" \
      io.portcullis.snr.upstream-commit="${SNR_COMMIT}" \
      io.portcullis.snr.patch-sha256="${PATCH_SHA256}"
# nsenter: the agent's reboot (/proc/sysrq-trigger on the host) and its
# modprobe softdog; bash: the reboot command's shell.
RUN apk add --no-cache util-linux-misc=2.42.3-r1 bash=5.3.9-r1
COPY --from=builder /src/install/ /install/
COPY --from=builder /manager /manager
USER 65532:65532
ENTRYPOINT ["/manager"]
