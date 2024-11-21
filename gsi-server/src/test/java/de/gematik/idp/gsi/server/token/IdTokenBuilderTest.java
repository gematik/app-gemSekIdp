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

package de.gematik.idp.gsi.server.token;

import static de.gematik.idp.field.ClaimName.ALGORITHM;
import static de.gematik.idp.field.ClaimName.AUDIENCE;
import static de.gematik.idp.field.ClaimName.AUTHENTICATION_CLASS_REFERENCE;
import static de.gematik.idp.field.ClaimName.AUTHENTICATION_METHODS_REFERENCE;
import static de.gematik.idp.field.ClaimName.EXPIRES_AT;
import static de.gematik.idp.field.ClaimName.ISSUED_AT;
import static de.gematik.idp.field.ClaimName.ISSUER;
import static de.gematik.idp.field.ClaimName.NONCE;
import static de.gematik.idp.field.ClaimName.SUBJECT;
import static de.gematik.idp.field.ClaimName.TELEMATIK_GIVEN_NAME;
import static de.gematik.idp.field.ClaimName.TELEMATIK_ID;
import static de.gematik.idp.field.ClaimName.TELEMATIK_ORGANIZATION;
import static de.gematik.idp.field.ClaimName.TELEMATIK_PROFESSION;
import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.idp.IdpConstants;
import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.crypto.KeyUtility;
import de.gematik.idp.file.ResourceReader;
import de.gematik.idp.tests.PkiKeyResolver;
import de.gematik.idp.token.JsonWebToken;
import java.security.PrivateKey;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import lombok.SneakyThrows;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(PkiKeyResolver.class)
class IdTokenBuilderTest {
  static {
    Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    Security.insertProviderAt(new BouncyCastleProvider(), 1);
  }

  private static final String uriIdpServer = "https://idp4711.de";
  private IdTokenBuilder idTokenBuilder;

  @SneakyThrows
  @BeforeEach
  public void init() {
    final PrivateKey clientPrivateKey =
        KeyUtility.readX509PrivateKeyPlain(
            ResourceReader.getFileFromResourceAsTmpFile("keys/ref-gsi-sig-privkey.pem"));

    idTokenBuilder =
        new IdTokenBuilder(
            new IdpJwtProcessor(clientPrivateKey, "ref-es-sig"),
            uriIdpServer,
            "NONCE123456",
            "http://NonSmokersFachdienst.de",
            Map.ofEntries(
                Map.entry(TELEMATIK_GIVEN_NAME.getJoseName(), "Vincent Vega"),
                Map.entry(TELEMATIK_ID.getJoseName(), "47119"),
                Map.entry(TELEMATIK_ORGANIZATION.getJoseName(), "NonSmokersWorldWide"),
                Map.entry(TELEMATIK_PROFESSION.getJoseName(), "Smoker"),
                Map.entry(
                    AUTHENTICATION_CLASS_REFERENCE.getJoseName(), IdpConstants.EIDAS_LOA_HIGH),
                Map.entry(
                    AUTHENTICATION_METHODS_REFERENCE.getJoseName(),
                    new String[] {"urn:telematik:auth:eID"})));
  }

  @Test
  void test_checkIdTokenClaims_VALID() {
    final JsonWebToken idToken = idTokenBuilder.buildIdToken();

    assertThat(idToken.getBodyClaims())
        .containsEntry(ISSUER.getJoseName(), uriIdpServer)
        .containsKey(SUBJECT.getJoseName())
        .containsKey(ISSUED_AT.getJoseName())
        .containsKey(EXPIRES_AT.getJoseName())
        .containsEntry(AUDIENCE.getJoseName(), "http://NonSmokersFachdienst.de")
        .containsKey(NONCE.getJoseName())
        .containsEntry(AUTHENTICATION_CLASS_REFERENCE.getJoseName(), IdpConstants.EIDAS_LOA_HIGH)
        .containsEntry(
            AUTHENTICATION_METHODS_REFERENCE.getJoseName(),
            new ArrayList<>(List.of("urn:telematik:auth:eID")))
        .containsEntry(TELEMATIK_PROFESSION.getJoseName(), "Smoker")
        .containsEntry(TELEMATIK_ORGANIZATION.getJoseName(), "NonSmokersWorldWide")
        .containsEntry(TELEMATIK_ID.getJoseName(), "47119")
        .containsEntry(TELEMATIK_GIVEN_NAME.getJoseName(), "Vincent Vega");

    assertThat(idToken.getHeaderClaims())
        .containsKey(ALGORITHM.getJoseName())
        .doesNotContainKey(EXPIRES_AT.getJoseName())
        .doesNotContainKey("headerNotCopy");
  }
}
