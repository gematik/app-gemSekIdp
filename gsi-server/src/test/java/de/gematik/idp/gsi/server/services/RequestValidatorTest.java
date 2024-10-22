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

package de.gematik.idp.gsi.server.services;

import static de.gematik.idp.gsi.server.common.Constants.ENTITY_STMNT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2043;
import static de.gematik.idp.gsi.server.controller.FedIdpController.AUTH_CODE_LENGTH;
import static de.gematik.idp.gsi.server.data.GsiConstants.*;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;

import de.gematik.idp.crypto.CryptoLoader;
import de.gematik.idp.crypto.Nonce;
import de.gematik.idp.field.ClientUtilities;
import de.gematik.idp.gsi.server.configuration.GsiConfiguration;
import de.gematik.idp.gsi.server.data.FedIdpAuthSession;
import de.gematik.idp.gsi.server.data.RpToken;
import de.gematik.idp.gsi.server.exceptions.GsiException;
import de.gematik.idp.token.JsonWebToken;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Set;
import lombok.SneakyThrows;
import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.annotation.DirtiesContext.ClassMode;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@DirtiesContext(classMode = ClassMode.AFTER_CLASS)
class RequestValidatorTest {

  @Autowired GsiConfiguration gsiConfiguration;

  private static final String CERT1_FROM_REQUEST =
      "-----BEGIN%20CERTIFICATE-----%0AMIIDszCCApugAwIBAgIUY%2FqefKABeWr36nT%2Brw9hJsbYFu8wDQYJKoZIhvcNAQEL%0ABQAwdjELMAkGA1UEBhMCREUxDzANBgNVBAgMBkJlcmxpbjEPMA0GA1UEBwwGQmVy%0AbGluMRkwFwYDVQQKDBBnZW1hdGlrVEVTVC1PTkxZMQ8wDQYDVQQLDAZQVCBJRE0x%0AGTAXBgNVBAMMEGZhZGlUbHNDbGllbnRSc2EwHhcNMjQwNjEzMDcxNjUyWhcNMjUw%0ANjEzMDcxNjUyWjB2MQswCQYDVQQGEwJERTEPMA0GA1UECAwGQmVybGluMQ8wDQYD%0AVQQHDAZCZXJsaW4xGTAXBgNVBAoMEGdlbWF0aWtURVNULU9OTFkxDzANBgNVBAsM%0ABlBUIElETTEZMBcGA1UEAwwQZmFkaVRsc0NsaWVudFJzYTCCASIwDQYJKoZIhvcN%0AAQEBBQADggEPADCCAQoCggEBAKiQaMTyY%2FlTTO9V4YJq7xsfN8l0%2BSqe2rRRasVU%0A8wenG8eohk99d1i5%2Fh08%2B%2BK1A5FX9GxgWh0RXGotpvbVvM7kzdOWxBJIK7j68R9g%0A%2F6B%2BKKO89rywLiJkxRT%2BOA4dusqocGDKmqFYZC1ntt2nSsSLlX3OuDC%2F1Thlhz2i%0AEGtweuYRL3zPeDXiegdyjRCY%2F9Xe%2FwaC4amuuJ5JkE5EsM0mL09kfkZCzdx8j2KK%0AqYTH2TYmiOG16CIVyZi9pE%2BKEHw95MIIcrzrO6QLWXcl7Y82rwVeeoUSicLBEydd%0A4YmsZ6pp%2BKGH0b9ycQO%2Bxs2uv79%2B5Zza9Q4OazEka4N0LyMCAwEAAaM5MDcwCQYD%0AVR0TBAIwADALBgNVHQ8EBAMCBeAwHQYDVR0OBBYEFMmogwgia7kONxur5UWBDX5g%0ABP0HMA0GCSqGSIb3DQEBCwUAA4IBAQAFK6nct1YVLMR6Tznh6ZrsvYs0UzCElUGM%0AnJtYaeCTgQPVKigQC4SPf%2FJp9qychooSbS7gbponndXgGIz8VFmt9y4d4q0uZKOr%0ALp7qcK%2BgQdvBts5TDZH20IiwW5b6VyGp%2Fos8fqR8WIt7fHdNz6Mu1fh2HsB4YjV9%0AxbbXTcKSzS6TROzh9bt2ubFX4ex56j6Mniy3DNF6zsW4kdh7naB%2FLfXvtH276Gj%2B%0AInhaF1sBLI8IIyQ5K2q2MJaly%2F8wiOys7FuG7duD1Lmh2kRO0FZkXsaQJmbZncUs%0A%2B4tgmnpEVgZ0FlKQ1BDAl0o0e7QbVRMiI2gjz7itOWFiUXvnMNIA%0A-----END%20CERTIFICATE-----%0A";

  private static final RpToken VALID_RPTOKEN =
      new RpToken(new JsonWebToken(ENTITY_STMNT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2043));

  private X509Certificate cert1FromEntityStmtRpService;
  private X509Certificate cert2FromEntityStmtRpService;

  @SneakyThrows
  @BeforeAll
  void setup() {

    cert1FromEntityStmtRpService =
        CryptoLoader.getCertificateFromPem(
            java.net.URLDecoder.decode(CERT1_FROM_REQUEST, StandardCharsets.UTF_8).getBytes());

    cert2FromEntityStmtRpService =
        CryptoLoader.getCertificateFromPem(
            FileUtils.readFileToByteArray(
                new File("src/test/resources/keys/ref-key-rotation.crt")));
  }

  @Test
  void test_validateParParams_VALID() {
    final String correctRedirectUri = "https://redirect.testsuite.gsi";
    assertDoesNotThrow(
        () ->
            RequestValidator.validateParParams(
                VALID_RPTOKEN, correctRedirectUri, "urn:telematik:versicherter openid"));
  }

  @ValueSource(
      strings = {
        "urn:telematik:geburtsdatumurn:telematik:alter openid",
        "urn%3Atelematik%3Adisplay_name",
        "urn:telematik:given_name+openid",
        "urn:telematik:schlecht openid"
      })
  @ParameterizedTest(name = "checkException_verifyInvalidScopes scope: {0}")
  void test_validateParParams_checkException_verifyInvalidScopes_VALID(final String scope) {
    final String correctRedirectUri = "https://redirect.testsuite.gsi";

    assertThatThrownBy(
            () -> RequestValidator.validateParParams(VALID_RPTOKEN, correctRedirectUri, scope))
        .isInstanceOf(GsiException.class)
        .hasMessageContaining(
            "Content of parameter scope [" + scope + "] exceeds scopes found in entity statement.");
  }

  @Test
  void test_validateCertificate_match_VALID() {

    try (final MockedStatic<EntityStatementRpReader> mockedStatic =
        Mockito.mockStatic(EntityStatementRpReader.class)) {
      mockedStatic
          .when(() -> EntityStatementRpReader.getRpTlsClientCerts(any()))
          .thenReturn(List.of(cert2FromEntityStmtRpService, cert1FromEntityStmtRpService));

      assertDoesNotThrow(
          () ->
              RequestValidator.validateCertificate(
                  CERT1_FROM_REQUEST, VALID_RPTOKEN, gsiConfiguration.isClientCertRequired()));
    }
  }

  @Test
  void test_validateCertificate_noMatch_INVALID() {

    try (final MockedStatic<EntityStatementRpReader> mockedStatic =
        Mockito.mockStatic(EntityStatementRpReader.class)) {
      mockedStatic
          .when(() -> EntityStatementRpReader.getRpTlsClientCerts(any()))
          .thenReturn(List.of(cert2FromEntityStmtRpService));

      assertThatThrownBy(
              () ->
                  RequestValidator.validateCertificate(
                      CERT1_FROM_REQUEST, VALID_RPTOKEN, gsiConfiguration.isClientCertRequired()))
          .isInstanceOf(GsiException.class)
          .hasMessageContaining(
              "client certificate in tls handshake does not match any certificate in entity"
                  + " statement/signed_jwks");
    }
  }

  @Test
  void test_validateCertificate_noTlsCert_INVALID() {

    assertThatThrownBy(
            () ->
                RequestValidator.validateCertificate(
                    "noTlsCert", VALID_RPTOKEN, gsiConfiguration.isClientCertRequired()))
        .isInstanceOf(GsiException.class)
        .hasMessageContaining(
            "client certificate in tls handshake is not a valid x509 certificate");
  }

  @Test
  void test_validateCertificate_certIsRequired_INVALID() {
    assertThatThrownBy(() -> RequestValidator.validateCertificate(null, VALID_RPTOKEN, true))
        .isInstanceOf(GsiException.class)
        .hasMessageContaining("client certificate is missing");
  }

  @Test
  void test_validateAuthRequestParams_VALID() {

    final FedIdpAuthSession session =
        FedIdpAuthSession.builder()
            .fachdienstClientId("http://localhost:8080")
            .fachdienstState("")
            .fachdienstCodeChallenge("")
            .fachdienstCodeChallengeMethod("")
            .fachdienstNonce("")
            .requestedOptionalClaims(Set.of())
            .fachdienstRedirectUri("")
            .authorizationCode(Nonce.getNonceAsHex(AUTH_CODE_LENGTH))
            .expiresAt(
                ZonedDateTime.now().plusSeconds(gsiConfiguration.getRequestUriTTL()).toString())
            .build();
    assertDoesNotThrow(
        () -> RequestValidator.validateAuthRequestParams(session, "http://localhost:8080"));
  }

  @Test
  void test_validateAuthRequestParams_throwsException_INVALID() {

    final FedIdpAuthSession session =
        FedIdpAuthSession.builder()
            .fachdienstClientId("http://localhost:8080")
            .fachdienstState("")
            .fachdienstCodeChallenge("")
            .fachdienstCodeChallengeMethod("")
            .fachdienstNonce("")
            .requestedOptionalClaims(Set.of())
            .fachdienstRedirectUri("")
            .authorizationCode(Nonce.getNonceAsHex(AUTH_CODE_LENGTH))
            .expiresAt(
                ZonedDateTime.now().plusSeconds(gsiConfiguration.getRequestUriTTL()).toString())
            .build();
    assertThatThrownBy(
            () -> RequestValidator.validateAuthRequestParams(session, "http://localhost:8083"))
        .isInstanceOf(GsiException.class)
        .hasMessageContaining("unknown client_id");
  }

  @Test
  void test_verifyRedirectUri_VALID() {
    assertDoesNotThrow(
        () ->
            RequestValidator.verifyRedirectUri(
                "http://localhost:8080/AS", "http://localhost:8080/AS"));
  }

  @Test
  void test_verifyRedirectUri_throwsException_INVALID() {
    assertThatThrownBy(
            () ->
                RequestValidator.verifyRedirectUri(
                    "http://localhost:8080/AS", "http://localhost:8080/AUTH"))
        .isInstanceOf(GsiException.class)
        .hasMessageContaining("invalid redirect_uri");
  }

  @Test
  void test_verifyCodeVerifier_VALID() {
    final String codeVerifier = ClientUtilities.generateCodeVerifier();
    final String codeChallenge = ClientUtilities.generateCodeChallenge(codeVerifier);
    assertDoesNotThrow(() -> RequestValidator.verifyCodeVerifier(codeVerifier, codeChallenge));
  }

  @Test
  void test_verifyCodeVerifier_throwsException_INVALID() {
    final String codeVerifier = ClientUtilities.generateCodeVerifier();
    final String invalidCodeChallenge = ClientUtilities.generateCodeChallenge("anyCodeVerifier");
    assertThatThrownBy(
            () -> RequestValidator.verifyCodeVerifier(codeVerifier, invalidCodeChallenge))
        .isInstanceOf(GsiException.class)
        .hasMessageContaining("invalid code_verifier");
  }

  @Test
  void test_verifyClientId_VALID() {
    assertDoesNotThrow(
        () -> RequestValidator.verifyClientId("http://localhost:8080", "http://localhost:8080"));
  }

  @Test
  void test_verifyClientId_throwsException_INVALID() {
    assertThatThrownBy(
            () -> RequestValidator.verifyClientId("http://localhost:8080", "http://localhost:8083"))
        .isInstanceOf(GsiException.class)
        .hasMessageContaining("invalid client_id");
  }

  @Test
  void test_verifyIdpDoesSupportRequestedScopes_VALID() {
    assertDoesNotThrow(
        () ->
            RequestValidator.verifyIdpDoesSupportRequestedScopes(
                "urn:telematik:display_name urn:telematik:versicherter openid"));
  }

  @Test
  void test_verifyIdpDoesSupportRequestedScopes_throwsException_INVALID() {
    assertThatThrownBy(
            () ->
                RequestValidator.verifyIdpDoesSupportRequestedScopes(
                    "urn:telematik:kvnr urn:telematik:versicherter openid"))
        .isInstanceOf(GsiException.class)
        .hasMessageContaining("More scopes requested in PAR than supported.");
  }

  @Test
  void test_validateAcrAmrCombination_validAcr_High_VALID() {
    final Set<String> acrHigh = Set.of(ACR_HIGH);

    assertDoesNotThrow(() -> RequestValidator.validateAmrAcrCombination(acrHigh, AMR_VALUES_HIGH));
  }

  @Test
  void test_validateAcrAmrCombination_invalidAcr_High_INVALID() {
    final Set<String> acrHigh = Set.of(ACR_HIGH);
    assertThatThrownBy(() -> RequestValidator.validateAmrAcrCombination(acrHigh, AMR_VALUES))
        .isInstanceOf(GsiException.class)
        .hasMessageContaining("invalid combination of essential values acr and amr");
  }

  @Test
  void test_validateAcrAmrCombination_validAcr_Substantial_VALID() {
    final Set<String> acrSubstantial = Set.of(ACR_SUBSTANTIAL);
    assertDoesNotThrow(
        () -> RequestValidator.validateAmrAcrCombination(acrSubstantial, AMR_VALUES_SUBSTANTIAL));
  }

  @Test
  void test_validateAcrAmrCombination_invalidAcr_Substantial_INVALID() {
    final Set<String> acrSubstantial = Set.of(ACR_SUBSTANTIAL);
    assertThatThrownBy(() -> RequestValidator.validateAmrAcrCombination(acrSubstantial, AMR_VALUES))
        .isInstanceOf(GsiException.class)
        .hasMessageContaining("invalid combination of essential values acr and amr");
  }

  @Test
  void test_validateAcrAmrCombination_validAcr_SubstantialAndHigh_VALID() {
    assertDoesNotThrow(() -> RequestValidator.validateAmrAcrCombination(ACR_VALUES, AMR_VALUES));
  }

  @Test
  void test_validateAcrAmrCombination_invalidAcr_INVALID() {
    final Set<String> acrInvalid = Set.of(ACR_SUBSTANTIAL, "invalidAcr");
    assertThatThrownBy(
            () -> RequestValidator.validateAmrAcrCombination(acrInvalid, AMR_VALUES_SUBSTANTIAL))
        .isInstanceOf(GsiException.class)
        .hasMessageContaining("invalid acr value");
  }

  @Test
  void test_validateAcrAmrCombination_invalidAmr_INVALID() {
    final Set<String> acrHigh = Set.of(ACR_HIGH);
    final Set<String> amrInvalid = Set.of("urn:telematik:auth:eGK", "urn:telematik:auth:invalid");
    assertThatThrownBy(() -> RequestValidator.validateAmrAcrCombination(acrHigh, amrInvalid))
        .isInstanceOf(GsiException.class)
        .hasMessageContaining("invalid amr value");
  }
}
