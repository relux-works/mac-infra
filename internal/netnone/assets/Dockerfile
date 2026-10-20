FROM eclipse-temurin:17-jdk@sha256:fe947d993c32dd9cf651a4353a6ed723c2370b3a9d034ea4cab4775404ea531a
RUN groupadd --gid 10001 netnone && useradd --uid 10001 --gid 10001 --create-home --home-dir /home/netnone netnone
USER root
RUN install -d -o 10001 -g 10001 /work /gradle
USER netnone
