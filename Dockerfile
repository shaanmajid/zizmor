# ------------------------------------------------------------------------------
# Prep image
#
# Observe that we do something wonky here: the "right" way to bootstrap
# zizmor is to directly install it from `apk`, since Wolfi OS provides a build.
#
# However, that doesn't work for us in practice, since Wolfi's downstream
# cadence can diverge significantly (24+ hours) from ours. We previously
# accepted that but now need faster turnarounds, so we use Wolfi OS to
# bootstrap uv and then `uv tool install` to bootstrap the right arch-specific
# binary. This also saves us a re-build of zizmor since we can re-use the PyPI
# builds.
# ------------------------------------------------------------------------------

FROM cgr.dev/chainguard/wolfi-base:latest@sha256:003627df3c1e1bba0c4116afcddb314aca9594ee2328c7e876a8081a6c988b2e AS wolfi-base

FROM wolfi-base AS prep

ARG ZIZMOR_VERSION

RUN set -eux && \
    apk update && \
    apk add uv

# installs to `/root/.local/bin/zizmor`
RUN uv tool install zizmor==${ZIZMOR_VERSION}

# ------------------------------------------------------------------------------
# Runtime image
# ------------------------------------------------------------------------------

FROM wolfi-base

COPY --from=prep /root/.local/bin/zizmor /usr/bin/zizmor

# smoke test
RUN /usr/bin/zizmor --version

ENTRYPOINT ["/usr/bin/zizmor"]
