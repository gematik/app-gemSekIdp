/*
 *  Copyright 2023 gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.idp.gsi.server.data;

import static de.gematik.idp.gsi.server.controller.FedIdpController.AUTH_CODE_LENGTH;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import de.gematik.idp.crypto.Nonce;
import de.gematik.idp.gsi.server.util.ClaimHelper;
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
        new HashSet<>(
            Arrays.asList(
                "urn:telematik:display_name",
                "urn:telematik:alter",
                "openid",
                "urn:telematik:email"));

    final FedIdpAuthSession fedIdpAuthSession =
        FedIdpAuthSession.builder()
            .fachdienstCodeChallenge("fachdienstCodeChallenge")
            .fachdienstCodeChallengeMethod("fachdienstCodeChallengeMethod")
            .fachdienstNonce("fachdienstNonce")
            .requestedOptionalClaims(ClaimHelper.getClaimsForScopeSet(scopes))
            .fachdienstRedirectUri("fachdienstRedirectUri")
            .authorizationCode(Nonce.getNonceAsHex(AUTH_CODE_LENGTH))
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
    assertThat(fedIdpAuthSession.getRequestedOptionalClaims())
        .isEqualTo(
            Set.of(
                "urn:telematik:claims:display_name",
                "urn:telematik:claims:alter",
                "urn:telematik:claims:email"));

    assertThat(FedIdpAuthSession.builder().toString()).hasSizeGreaterThan(0);
  }
}
