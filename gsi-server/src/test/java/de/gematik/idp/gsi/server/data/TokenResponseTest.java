package de.gematik.idp.gsi.server.data;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import org.junit.jupiter.api.Test;

class TokenResponseTest {

  public static final int EXPIRES_IN = 300;

  @Test
  void testBuild() {
    final TokenResponse tokenResponse =
        TokenResponse.builder()
            .idToken("ID_TOKEN")
            .accessToken("ACCESS_TOKEN")
            .tokenType("Bearer")
            .expiresIn(EXPIRES_IN)
            .build();
    assertThat(tokenResponse).isNotNull();
    assertThat(tokenResponse.getIdToken()).isEqualTo("ID_TOKEN");
    assertThat(tokenResponse.getExpiresIn()).isEqualTo(EXPIRES_IN);
    assertThat(tokenResponse.getIdToken()).isEqualTo("ID_TOKEN");
    assertThat(tokenResponse.getTokenType()).isEqualTo("Bearer");

    assertThat(TokenResponse.builder().toString()).hasSizeGreaterThan(0);
  }
}
