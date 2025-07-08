/*
 * Copyright (Change Date see Readme), gematik GmbH
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
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 */

package de.gematik.idp.gsi.server.token;

import static de.gematik.idp.field.ClaimName.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import de.gematik.idp.IdpConstants;
import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.crypto.CryptoLoader;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.tests.PkiKeyResolver;
import de.gematik.idp.token.JsonWebToken;
import java.io.InputStream;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import lombok.SneakyThrows;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.util.StreamUtils;

@ExtendWith(PkiKeyResolver.class)
class IdTokenBuilderTest {
  static {
    Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    Security.insertProviderAt(new BouncyCastleProvider(), 1);
  }

  private static final String uriIdpServer = "https://idp4711.de";
  private IdTokenBuilder idTokenBuilder;

  private PkiIdentity pkiIdentity;

  @SneakyThrows
  @BeforeEach
  public void init() {

    try (final InputStream inputStream =
        getClass().getClassLoader().getResourceAsStream("certs/ref-gsi-sig.p12")) {
      assertNotNull(inputStream, "The p12 file should exist in resources");
      pkiIdentity = CryptoLoader.getIdentityFromP12(StreamUtils.copyToByteArray(inputStream), "00");
    }
  }

  @ValueSource(strings = {"1.0.0", "2.0.0"})
  @ParameterizedTest(name = "test_getTokensForCode_200 idTokenVersion: {0}")
  void test_checkIdTokenClaims_VALID(final String idTokenVersion) {

    idTokenBuilder =
        new IdTokenBuilder(
            new IdpJwtProcessor(pkiIdentity, Optional.of("puk_fed_idp_token")),
            uriIdpServer,
            "NONCE123456",
            "http://NonSmokersFachdienst.de",
            idTokenVersion,
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
        .containsOnlyKeys(
            ALGORITHM.getJoseName(),
            KEY_ID.getJoseName(),
            TYPE.getJoseName(),
            X509_CERTIFICATE_CHAIN.getJoseName(),
            "version");

    assertThat(idToken.getHeaderClaims()).containsEntry("version", idTokenVersion);
  }

  @ValueSource(strings = {"2.0.0", "1.0.0"})
  @ParameterizedTest(name = "test_getTokensForCode_200 idTokenVersion: {0}")
  void test_checkIdTokenClaims_substantial_mew_VALID(final String idTokenVersion) {

    idTokenBuilder =
        new IdTokenBuilder(
            new IdpJwtProcessor(pkiIdentity, Optional.of("puk_fed_idp_token")),
            uriIdpServer,
            "NONCE123456",
            "http://NonSmokersFachdienst.de",
            idTokenVersion,
            Map.ofEntries(
                Map.entry(TELEMATIK_GIVEN_NAME.getJoseName(), "Vincent Vega"),
                Map.entry(TELEMATIK_ID.getJoseName(), "47119"),
                Map.entry(TELEMATIK_ORGANIZATION.getJoseName(), "NonSmokersWorldWide"),
                Map.entry(TELEMATIK_PROFESSION.getJoseName(), "Smoker"),
                Map.entry(
                    AUTHENTICATION_CLASS_REFERENCE.getJoseName(),
                    IdpConstants.EIDAS_LOA_SUBSTANTIAL),
                Map.entry(
                    AUTHENTICATION_METHODS_REFERENCE.getJoseName(),
                    new String[] {"urn:telematik:auth:mEW"})));

    final JsonWebToken idToken = idTokenBuilder.buildIdToken();

    final String expectedAmr =
        idTokenVersion.equals("2.0.0") ? "urn:telematik:auth:other" : "urn:telematik:auth:mEW";

    assertThat(idToken.getBodyClaims())
        .containsEntry(ISSUER.getJoseName(), uriIdpServer)
        .containsKey(SUBJECT.getJoseName())
        .containsKey(ISSUED_AT.getJoseName())
        .containsKey(EXPIRES_AT.getJoseName())
        .containsEntry(AUDIENCE.getJoseName(), "http://NonSmokersFachdienst.de")
        .containsKey(NONCE.getJoseName())
        .containsEntry(
            AUTHENTICATION_CLASS_REFERENCE.getJoseName(), IdpConstants.EIDAS_LOA_SUBSTANTIAL)
        .containsEntry(
            AUTHENTICATION_METHODS_REFERENCE.getJoseName(), new ArrayList<>(List.of(expectedAmr)))
        .containsEntry(TELEMATIK_PROFESSION.getJoseName(), "Smoker")
        .containsEntry(TELEMATIK_ORGANIZATION.getJoseName(), "NonSmokersWorldWide")
        .containsEntry(TELEMATIK_ID.getJoseName(), "47119")
        .containsEntry(TELEMATIK_GIVEN_NAME.getJoseName(), "Vincent Vega");

    if (idTokenVersion.equals("2.0.0")) {
      assertThat(idToken.getBodyClaims())
          .containsEntry("urn:telematik:auth:consent", List.of("loa-substantial"));
    }

    assertThat(idToken.getHeaderClaims())
        .containsOnlyKeys(
            ALGORITHM.getJoseName(),
            KEY_ID.getJoseName(),
            TYPE.getJoseName(),
            X509_CERTIFICATE_CHAIN.getJoseName(),
            "version");
    assertThat(idToken.getHeaderClaims()).containsEntry("version", idTokenVersion);
  }

  @ValueSource(strings = {"2.0.0", "1.0.0"})
  @ParameterizedTest(name = "test_getTokensForCode_200 idTokenVersion: {0}")
  void test_checkIdTokenClaims_substantial_sso_VALID(final String idTokenVersion) {

    idTokenBuilder =
        new IdTokenBuilder(
            new IdpJwtProcessor(pkiIdentity, Optional.of("puk_fed_idp_token")),
            uriIdpServer,
            "NONCE123456",
            "http://NonSmokersFachdienst.de",
            idTokenVersion,
            Map.ofEntries(
                Map.entry(TELEMATIK_GIVEN_NAME.getJoseName(), "Vincent Vega"),
                Map.entry(TELEMATIK_ID.getJoseName(), "47119"),
                Map.entry(TELEMATIK_ORGANIZATION.getJoseName(), "NonSmokersWorldWide"),
                Map.entry(TELEMATIK_PROFESSION.getJoseName(), "Smoker"),
                Map.entry(
                    AUTHENTICATION_CLASS_REFERENCE.getJoseName(),
                    IdpConstants.EIDAS_LOA_SUBSTANTIAL),
                Map.entry(
                    AUTHENTICATION_METHODS_REFERENCE.getJoseName(),
                    new String[] {"urn:telematik:auth:sso"})));

    final JsonWebToken idToken = idTokenBuilder.buildIdToken();

    final String expectedAmr =
        idTokenVersion.equals("2.0.0") ? "urn:telematik:auth:other" : "urn:telematik:auth:sso";

    assertThat(idToken.getBodyClaims())
        .containsEntry(ISSUER.getJoseName(), uriIdpServer)
        .containsKey(SUBJECT.getJoseName())
        .containsKey(ISSUED_AT.getJoseName())
        .containsKey(EXPIRES_AT.getJoseName())
        .containsEntry(AUDIENCE.getJoseName(), "http://NonSmokersFachdienst.de")
        .containsKey(NONCE.getJoseName())
        .containsEntry(
            AUTHENTICATION_CLASS_REFERENCE.getJoseName(), IdpConstants.EIDAS_LOA_SUBSTANTIAL)
        .containsEntry(
            AUTHENTICATION_METHODS_REFERENCE.getJoseName(), new ArrayList<>(List.of(expectedAmr)))
        .containsEntry(TELEMATIK_PROFESSION.getJoseName(), "Smoker")
        .containsEntry(TELEMATIK_ORGANIZATION.getJoseName(), "NonSmokersWorldWide")
        .containsEntry(TELEMATIK_ID.getJoseName(), "47119")
        .containsEntry(TELEMATIK_GIVEN_NAME.getJoseName(), "Vincent Vega");

    if (idTokenVersion.equals("2.0.0")) {
      assertThat(idToken.getBodyClaims())
          .containsEntry("urn:telematik:auth:interactive", "silent")
          .containsEntry("urn:telematik:auth:consent", List.of("loa-substantial"));
    }

    assertThat(idToken.getHeaderClaims())
        .containsOnlyKeys(
            ALGORITHM.getJoseName(),
            KEY_ID.getJoseName(),
            TYPE.getJoseName(),
            X509_CERTIFICATE_CHAIN.getJoseName(),
            "version");
    assertThat(idToken.getHeaderClaims()).containsEntry("version", idTokenVersion);
  }
}
