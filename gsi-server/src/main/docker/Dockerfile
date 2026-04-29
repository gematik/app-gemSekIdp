FROM gematik1/osadl-alpine-openjdk21-jre:1.0.11@sha256:d4495f442e5798e4d07ac149b79ef7b34128be5d01570861ffc9c5e7b22c0f7e
ARG COMMIT_HASH
ARG VERSION

LABEL de.gematik.vendor="gematik GmbH" \
      maintainer="software-development@gematik.de" \
      de.gematik.app="Gematik Idp-Sektoral" \
      de.gematik.git-repo-name="...gem-sek-idp.git" \
      de.gematik.commit-sha=$COMMIT_HASH \
      de.gematik.version=$VERSION
      
# The STOPSIGNAL instruction sets the system call signal that will be sent to the container to exit
# SIGTERM = 15 - https://de.wikipedia.org/wiki/Signal_(Unix)
STOPSIGNAL SIGTERM

HEALTHCHECK --interval=15s \
            --timeout=10s \
            --start-period=30s \
            --retries=3 \
  CMD ["/usr/bin/wget", "--quiet", "--tries=1", "--spider", \
       "http://localhost:8180/actuator/health"]

# Default USERID and GROUPID
ARG USERID=10000
ARG GROUPID=10000

# Run as User (not root)
USER $USERID:$GROUPID

COPY --chown=$USERID:$GROUPID gsi-server*.jar /app/gsi-server.jar
WORKDIR /app

CMD ["java", "-jar", "/app/gsi-server.jar"]
