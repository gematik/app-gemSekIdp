package de.gematik.idp.gsi.server.services;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;

import java.net.URISyntaxException;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class SektoralIdpAuthenticatorTest {

  @Autowired SektoralIdpAuthenticator sektoralIdpAuthenticator;

  @Test
  void testCreateLocationForAuthorizationResponse() {
    final AtomicReference<String> location = new AtomicReference<>();

    Assertions.assertDoesNotThrow(
        () ->
            location.set(
                sektoralIdpAuthenticator.createLocationForAuthorizationResponse(
                    "uri1", "state1", "code1")));
    assertThat(location.get()).hasSizeGreaterThan(0);
  }

  @Test
  void testCreateLocationForAuthorizationResponseUriSyntaxException() {
    final AtomicReference<String> location = new AtomicReference<>();

    assertThatThrownBy(
            () ->
                location.set(
                    sektoralIdpAuthenticator.createLocationForAuthorizationResponse(
                        "%wrongUri", "state1", "code1")))
        .hasCauseInstanceOf(URISyntaxException.class);
  }
}
