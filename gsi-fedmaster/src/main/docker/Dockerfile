FROM eclipse-temurin:21-jre

ARG COMMIT_HASH
ARG VERSION

LABEL de.gematik.vendor="gematik GmbH" \
      maintainer="software-development@gematik.de" \
      de.gematik.app="IDP Federation POC - gsi-fedmaster" \
      de.gematik.git-repo-name="...gem-sek-idp.git" \
      de.gematik.commit-sha=$COMMIT_HASH \
      de.gematik.version=$VERSION

# The STOPSIGNAL instruction sets the system call signal that will be sent to the container to exit
# SIGTERM = 15 - https://de.wikipedia.org/wiki/Signal_(Unix)
STOPSIGNAL SIGTERM

HEALTHCHECK CMD curl --fail http://localhost:8080/actuator/health | grep UP || exit 1

# Default USERID and GROUPID
ARG USERID=10000
ARG GROUPID=10000

# Run as User (not root)
USER $USERID:$GROUPID

COPY --chown=$USERID:$GROUPID gsi-fedmaster*.jar /app/gsi-fedmaster.jar
WORKDIR /app

CMD ["java", "-jar", "/app/gsi-fedmaster.jar"]
