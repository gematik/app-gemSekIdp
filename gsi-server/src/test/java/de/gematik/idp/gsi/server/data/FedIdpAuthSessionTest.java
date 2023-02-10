package de.gematik.idp.gsi.server.data;

import static de.gematik.idp.gsi.server.controller.FedIdpController.AUTH_CODE_LENGTH;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import de.gematik.idp.crypto.Nonce;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.Test;

class FedIdpAuthSessionTest {

  @Test
  void testBuild() {
    final int REQUEST_URI_TTL_SECS = 42;
    final Set<String> scopes =
        new HashSet<>(Arrays.asList("profile", "telematik", "openid", "email"));

    final FedIdpAuthSession fedIdpAuthSession =
        FedIdpAuthSession.builder()
            .fachdienstCodeChallenge("fachdienstCodeChallenge")
            .fachdienstCodeChallengeMethod("fachdienstCodeChallengeMethod")
            .fachdienstNonce("fachdienstNonce")
            .requestedScopes(scopes)
            .fachdienstRedirectUri("fachdienstRedirectUri")
            .authorizationCode(Nonce.getNonceAsHex(AUTH_CODE_LENGTH))
            .requestUri("requestUri")
            .expiresAt(ZonedDateTime.now().plusSeconds(REQUEST_URI_TTL_SECS).toString())
            .build();

    assertThat(fedIdpAuthSession).isNotNull();
    assertThat(fedIdpAuthSession.getFachdienstCodeChallenge()).isEqualTo("fachdienstCodeChallenge");
    assertThat(fedIdpAuthSession.getExpiresAt()).hasSizeGreaterThan(0);
    assertThat(fedIdpAuthSession.getAuthorizationCode()).hasSize(AUTH_CODE_LENGTH);
    assertThat(fedIdpAuthSession.getFachdienstNonce()).isEqualTo("fachdienstNonce");
    assertThat(fedIdpAuthSession.getFachdienstRedirectUri()).isEqualTo("fachdienstRedirectUri");
    assertThat(fedIdpAuthSession.getFachdienstCodeChallengeMethod())
        .isEqualTo("fachdienstCodeChallengeMethod");
    assertThat(fedIdpAuthSession.getRequestUri()).isEqualTo("requestUri");
    assertThat(fedIdpAuthSession.getRequestedScopes()).isEqualTo(scopes);

    assertThat(FedIdpAuthSession.builder().toString()).hasSizeGreaterThan(0);
  }
}
