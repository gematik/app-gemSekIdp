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

package de.gematik.idp.gsi.server.controller;

import static de.gematik.idp.IdpConstants.FED_AUTH_ENDPOINT;
import static de.gematik.idp.IdpConstants.TOKEN_ENDPOINT;
import static de.gematik.idp.data.Oauth2ErrorCode.UNAUTHORIZED_CLIENT;
import static de.gematik.idp.gsi.server.data.GsiConstants.FEDIDP_PAR_AUTH_ENDPOINT;
import static de.gematik.idp.gsi.server.data.GsiConstants.FED_SIGNED_JWKS_ENDPOINT;
import static de.gematik.idp.gsi.server.data.GsiConstants.TLS_CLIENT_CERT_HEADER_NAME;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import de.gematik.idp.IdpConstants;
import de.gematik.idp.authentication.UriUtils;
import de.gematik.idp.crypto.CryptoLoader;
import de.gematik.idp.field.ClientUtilities;
import de.gematik.idp.field.CodeChallengeMethod;
import de.gematik.idp.gsi.server.GsiServer;
import de.gematik.idp.gsi.server.configuration.GsiConfiguration;
import de.gematik.idp.gsi.server.data.ClaimsResponse;
import de.gematik.idp.gsi.server.services.EntityStatementRpService;
import de.gematik.idp.token.IdpJwe;
import de.gematik.idp.token.JsonWebToken;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import kong.unirest.core.HttpResponse;
import kong.unirest.core.HttpStatus;
import kong.unirest.core.JsonNode;
import kong.unirest.core.Unirest;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;
import org.awaitility.Awaitility;
import org.jose4j.jwk.PublicJsonWebKey;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.annotation.DirtiesContext.ClassMode;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

@Slf4j
@ActiveProfiles("test-controller")
@SpringBootTest(classes = GsiServer.class, webEnvironment = WebEnvironment.RANDOM_PORT)
@DirtiesContext(classMode = ClassMode.AFTER_CLASS)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class FedIdpControllerTest {

  @DynamicPropertySource
  static void dynamicProperties(final DynamicPropertyRegistry registry) {
    registry.add("gsi.requestUriTTL", () -> 5);
  }

  @Autowired private EntityStatementRpService entityStatementRpService;
  static final List<String> OPENID_PROVIDER_CLAIMS =
      List.of(
          "issuer",
          "signed_jwks_uri",
          "organization_name",
          "logo_uri",
          "authorization_endpoint",
          "token_endpoint",
          "pushed_authorization_request_endpoint",
          "client_registration_types_supported",
          "subject_types_supported",
          "response_types_supported",
          "scopes_supported",
          "response_modes_supported",
          "grant_types_supported",
          "require_pushed_authorization_requests",
          "token_endpoint_auth_methods_supported",
          "request_authentication_methods_supported",
          "id_token_signing_alg_values_supported",
          "id_token_encryption_alg_values_supported",
          "id_token_encryption_enc_values_supported",
          "user_type_supported",
          "claims_supported",
          "claims_parameter_supported");

  @LocalServerPort private int serverPort;

  private TestInfo testInfo;
  private String testHostUrl;
  private HttpResponse<String> entityStatementResponseGood;
  private JsonWebToken entityStatement;

  private HttpResponse<String> sigendJwksResponseGood;
  private JsonWebToken sigendJwks;
  private Map<String, Object> entityStatementbodyClaims;
  @Autowired private GsiConfiguration gsiConfiguration;
  private final String certFromRequest =
      "-----BEGIN%20CERTIFICATE-----%0AMIIDszCCApugAwIBAgIUY%2FqefKABeWr36nT%2Brw9hJsbYFu8wDQYJKoZIhvcNAQEL%0ABQAwdjELMAkGA1UEBhMCREUxDzANBgNVBAgMBkJlcmxpbjEPMA0GA1UEBwwGQmVy%0AbGluMRkwFwYDVQQKDBBnZW1hdGlrVEVTVC1PTkxZMQ8wDQYDVQQLDAZQVCBJRE0x%0AGTAXBgNVBAMMEGZhZGlUbHNDbGllbnRSc2EwHhcNMjQwNjEzMDcxNjUyWhcNMjUw%0ANjEzMDcxNjUyWjB2MQswCQYDVQQGEwJERTEPMA0GA1UECAwGQmVybGluMQ8wDQYD%0AVQQHDAZCZXJsaW4xGTAXBgNVBAoMEGdlbWF0aWtURVNULU9OTFkxDzANBgNVBAsM%0ABlBUIElETTEZMBcGA1UEAwwQZmFkaVRsc0NsaWVudFJzYTCCASIwDQYJKoZIhvcN%0AAQEBBQADggEPADCCAQoCggEBAKiQaMTyY%2FlTTO9V4YJq7xsfN8l0%2BSqe2rRRasVU%0A8wenG8eohk99d1i5%2Fh08%2B%2BK1A5FX9GxgWh0RXGotpvbVvM7kzdOWxBJIK7j68R9g%0A%2F6B%2BKKO89rywLiJkxRT%2BOA4dusqocGDKmqFYZC1ntt2nSsSLlX3OuDC%2F1Thlhz2i%0AEGtweuYRL3zPeDXiegdyjRCY%2F9Xe%2FwaC4amuuJ5JkE5EsM0mL09kfkZCzdx8j2KK%0AqYTH2TYmiOG16CIVyZi9pE%2BKEHw95MIIcrzrO6QLWXcl7Y82rwVeeoUSicLBEydd%0A4YmsZ6pp%2BKGH0b9ycQO%2Bxs2uv79%2B5Zza9Q4OazEka4N0LyMCAwEAAaM5MDcwCQYD%0AVR0TBAIwADALBgNVHQ8EBAMCBeAwHQYDVR0OBBYEFMmogwgia7kONxur5UWBDX5g%0ABP0HMA0GCSqGSIb3DQEBCwUAA4IBAQAFK6nct1YVLMR6Tznh6ZrsvYs0UzCElUGM%0AnJtYaeCTgQPVKigQC4SPf%2FJp9qychooSbS7gbponndXgGIz8VFmt9y4d4q0uZKOr%0ALp7qcK%2BgQdvBts5TDZH20IiwW5b6VyGp%2Fos8fqR8WIt7fHdNz6Mu1fh2HsB4YjV9%0AxbbXTcKSzS6TROzh9bt2ubFX4ex56j6Mniy3DNF6zsW4kdh7naB%2FLfXvtH276Gj%2B%0AInhaF1sBLI8IIyQ5K2q2MJaly%2F8wiOys7FuG7duD1Lmh2kRO0FZkXsaQJmbZncUs%0A%2B4tgmnpEVgZ0FlKQ1BDAl0o0e7QbVRMiI2gjz7itOWFiUXvnMNIA%0A-----END%20CERTIFICATE-----%0A";
  private X509Certificate certFromEntityStmtRpService;
  private X509Certificate otherCert;

  @SneakyThrows
  @BeforeAll
  void setup() {
    testHostUrl = "http://localhost:" + serverPort;

    entityStatementResponseGood = retrieveEntityStatement();
    sigendJwksResponseGood = retrieveSignedJwks();
    assertThat(entityStatementResponseGood.getStatus()).isEqualTo(HttpStatus.OK);
    entityStatement = new JsonWebToken(entityStatementResponseGood.getBody());
    sigendJwks = new JsonWebToken(sigendJwksResponseGood.getBody());
    entityStatementbodyClaims = entityStatement.extractBodyClaims();

    certFromEntityStmtRpService =
        CryptoLoader.getCertificateFromPem(
            java.net.URLDecoder.decode(certFromRequest, StandardCharsets.UTF_8).getBytes());

    otherCert =
        CryptoLoader.getCertificateFromPem(
            FileUtils.readFileToByteArray(
                new File("src/test/resources/keys/fachdienstTlsC_TEST_ONLY.pem")));
  }

  @BeforeEach
  void init(final TestInfo testInfo) {
    this.testInfo = testInfo;
    log.info("START UNIT TEST: {}", testInfo.getDisplayName());
  }

  /************************** ENTITY_STATEMENT_ENDPOINT *****************/

  @Test
  void entityStatementResponse_ContentTypeEntityStatement() {
    assertThat(entityStatementResponseGood.getHeaders().get(HttpHeaders.CONTENT_TYPE).get(0))
        .isEqualTo("application/entity-statement+jwt;charset=UTF-8");
  }

  @Test
  void entityStatementResponse_JoseHeader() {
    assertThat(entityStatement.extractHeaderClaims()).containsOnlyKeys("typ", "alg", "kid");
  }

  @Test
  void entityStatement_BodyClaimsComplete() {
    assertThat(entityStatementbodyClaims)
        .containsOnlyKeys("iss", "sub", "iat", "exp", "jwks", "authority_hints", "metadata");
  }

  @Test
  void entityStatement_ContainsJwks() {
    assertThat(entityStatementbodyClaims.get("jwks")).isNotNull();
  }

  @Test
  void entityStatement_MetadataClaims() {
    final Map<String, Object> metadata = getInnerClaimMap(entityStatementbodyClaims, "metadata");
    assertThat(metadata).containsOnlyKeys("openid_provider", "federation_entity");
  }

  @Test
  void entityStatement_OpenidProviderClaimsComplete() {
    final Map<String, Object> metadata = getInnerClaimMap(entityStatementbodyClaims, "metadata");
    final Map<String, Object> openidProvider =
        Objects.requireNonNull(
            (Map<String, Object>) metadata.get("openid_provider"),
            "missing claim: openid_provider");

    assertThat(openidProvider).containsOnlyKeys(OPENID_PROVIDER_CLAIMS);
  }

  @SuppressWarnings("unchecked")
  @Test
  void entityStatement_OpenidProviderClaimsContentCorrect() {

    final String gsiServerUrl = "https://gsi.dev.gematik.solutions";
    final Map<String, Object> metadata = getInnerClaimMap(entityStatementbodyClaims, "metadata");
    final Map<String, Object> openidProvider =
        Objects.requireNonNull(
            (Map<String, Object>) metadata.get("openid_provider"),
            "missing claim: openid_provider");

    assertThat(openidProvider)
        .containsEntry("issuer", gsiServerUrl)
        .containsEntry("signed_jwks_uri", gsiServerUrl + "/jws.json");
    assertThat(openidProvider.get("organization_name")).asString().isNotEmpty();
    assertThat(openidProvider.get("logo_uri")).asString().isNotEmpty();
    assertThat(openidProvider)
        .containsEntry("authorization_endpoint", gsiServerUrl + "/auth")
        .containsEntry("token_endpoint", gsiConfiguration.getServerUrlMtls() + "/token")
        .containsEntry(
            "pushed_authorization_request_endpoint",
            gsiConfiguration.getServerUrlMtls() + "/PAR_Auth");
    assertThat((List) openidProvider.get("client_registration_types_supported"))
        .containsExactlyInAnyOrder("automatic");
    assertThat((List) openidProvider.get("subject_types_supported"))
        .hasSize(1)
        .isSubsetOf(List.of("pairwise", "public"));
    assertThat((List) openidProvider.get("response_types_supported"))
        .containsExactlyInAnyOrder("code");
    assertThat((List) openidProvider.get("scopes_supported"))
        .containsExactlyInAnyOrder(
            "urn:telematik:family_name",
            "urn:telematik:geburtsdatum",
            "urn:telematik:alter",
            "urn:telematik:display_name",
            "urn:telematik:given_name",
            "urn:telematik:geschlecht",
            "urn:telematik:email",
            "urn:telematik:versicherter",
            "openid");
    assertThat((List) openidProvider.get("response_modes_supported"))
        .containsExactlyInAnyOrder("query");
    assertThat((List) openidProvider.get("grant_types_supported"))
        .containsExactlyInAnyOrder("authorization_code");
    assertThat((Boolean) openidProvider.get("require_pushed_authorization_requests")).isTrue();
    assertThat((List) openidProvider.get("token_endpoint_auth_methods_supported"))
        .containsExactlyInAnyOrder("self_signed_tls_client_auth");
    assertThat(openidProvider.get("request_authentication_methods_supported"))
        .asString()
        .contains("ar", "par", "none", "self_signed_tls_client_auth");
    assertThat((List) openidProvider.get("id_token_signing_alg_values_supported"))
        .containsExactlyInAnyOrder("ES256");
    assertThat((List) openidProvider.get("id_token_encryption_alg_values_supported"))
        .containsExactlyInAnyOrder("ECDH-ES");
    assertThat((List) openidProvider.get("id_token_encryption_enc_values_supported"))
        .containsExactlyInAnyOrder("A256GCM");
    assertThat((List) openidProvider.get("user_type_supported"))
        .isSubsetOf(List.of("HCI", "HP", "IP"));
  }

  @SuppressWarnings("unchecked")
  @Test
  void entityStatement_FederationEntityClaimsContentCorrect() {
    final Map<String, Object> metadata = getInnerClaimMap(entityStatementbodyClaims, "metadata");
    final Map<String, Object> federationEntity =
        Objects.requireNonNull(
            (Map<String, Object>) metadata.get("federation_entity"),
            "missing claim: federation_entity");
    final ArrayList<String> contacts = new ArrayList<>();
    contacts.add("support@idp4711.de");
    contacts.add("idm@gematik.de");
    assertThat(federationEntity)
        .containsEntry("name", "gematik sektoraler IDP")
        .containsEntry("contacts", contacts)
        .containsEntry("homepage_uri", "https://idp4711.de");
  }

  @SuppressWarnings("unchecked")
  private Map<String, Object> getInnerClaimMap(
      final Map<String, Object> claimMap, final String key) {
    return Objects.requireNonNull((Map<String, Object>) claimMap.get(key), "missing claim: " + key);
  }

  private HttpResponse<String> retrieveEntityStatement() {
    return Unirest.get(testHostUrl + IdpConstants.ENTITY_STATEMENT_ENDPOINT).asString();
  }

  /************************** SIGNED_JWKS_ENDPOINT *****************/
  @Test
  void sigendJwksResponse_ContentTypeEntityStatement() {
    assertThat(sigendJwksResponseGood.getHeaders().get(HttpHeaders.CONTENT_TYPE).get(0))
        .isEqualTo("application/jwk-set+json;charset=UTF-8");
  }

  @Test
  void signedJwksResponse_JoseHeader() {
    assertThat(sigendJwks.extractHeaderClaims()).containsOnlyKeys("typ", "alg", "kid");
  }

  @Test
  void signedJwksResponse_BodyClaims() {
    assertThat(sigendJwks.extractBodyClaims()).containsOnlyKeys("keys", "iss", "iat");
  }

  @Test
  void signedJwksResponse_Keys() {
    final List<Map<String, Object>> keyList =
        (List<Map<String, Object>>) sigendJwks.getBodyClaims().get("keys");
    assertThat(keyList.get(0).keySet())
        .containsExactlyInAnyOrder("use", "kid", "kty", "crv", "x", "y", "alg");
  }

  @Test
  void signedJwksResponse_NumberOfKeys() {
    final List<Map<String, Object>> keyList =
        (List<Map<String, Object>>) sigendJwks.getBodyClaims().get("keys");
    assertThat(keyList).hasSize(2);
  }

  private HttpResponse<String> retrieveSignedJwks() {
    return Unirest.get(testHostUrl + FED_SIGNED_JWKS_ENDPOINT).asString();
  }

  /************************** FEDIDP_PUSHED AUTH_ENDPOINT *****************/
  @ValueSource(
      strings = {
        "urn:telematik:geburtsdatum urn:telematik:alter openid",
        "urn:telematik:display_name",
        "urn:telematik:given_name openid",
        "urn:telematik:geschlecht urn:telematik:versicherter urn:telematik:email"
      })
  @ParameterizedTest(name = "parRequest_validScope_ResponseStatus_CREATED scope: {0}")
  void parRequest_validScope_ResponseStatus_CREATED(final String scope) {

    Mockito.doNothing()
        .when(entityStatementRpService)
        .doAutoregistration(testHostUrl, testHostUrl + "/AS", scope);

    final HttpResponse<String> resp =
        Unirest.post(testHostUrl + FEDIDP_PAR_AUTH_ENDPOINT)
            .field("client_id", testHostUrl)
            .field("state", "state_Fachdienst")
            .field("redirect_uri", testHostUrl + "/AS")
            .field("code_challenge", "P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk")
            .field("code_challenge_method", CodeChallengeMethod.S256.toString())
            .field("response_type", "code")
            .field("nonce", "42")
            .field("scope", scope)
            .field("acr_values", "gematik-ehealth-loa-high")
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .asString();
    assertThat(resp.getStatus()).isEqualTo(HttpStatus.CREATED);
  }

  @ValueSource(strings = {"gematik-ehealth-loa-high", "gematik-ehealth-loa-substantial"})
  @ParameterizedTest(name = "parRequest_validAcrValue_ResponseStatus_CREATED acr: {0}")
  void parRequest_validAcrValue_ResponseStatus_CREATED(final String acr_value) {

    Mockito.doNothing()
        .when(entityStatementRpService)
        .doAutoregistration(testHostUrl, testHostUrl + "/AS", "urn:telematik:given_name openid");

    final HttpResponse<String> resp =
        Unirest.post(testHostUrl + FEDIDP_PAR_AUTH_ENDPOINT)
            .field("client_id", testHostUrl)
            .field("state", "state_Fachdienst")
            .field("redirect_uri", testHostUrl + "/AS")
            .field("code_challenge", "P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk")
            .field("code_challenge_method", CodeChallengeMethod.S256.toString())
            .field("response_type", "code")
            .field("nonce", "42")
            .field("scope", "urn:telematik:given_name openid")
            .field("acr_values", acr_value)
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .asString();
    assertThat(resp.getStatus()).isEqualTo(HttpStatus.CREATED);
  }

  /*
   *  message nr.2 ... message nr.7
   * test auto registration and session handling
   */
  @Test
  void parRequest_authRequestUriPar() {

    Mockito.doNothing()
        .when(entityStatementRpService)
        .doAutoregistration(testHostUrl, testHostUrl + "/AS", "urn:telematik:given_name openid");

    final HttpResponse<String> respMsg3 =
        Unirest.post(testHostUrl + FEDIDP_PAR_AUTH_ENDPOINT)
            .field("client_id", testHostUrl)
            .field("state", "state_Fachdienst")
            .field("redirect_uri", testHostUrl + "/AS")
            .field("code_challenge", "P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk")
            .field("code_challenge_method", CodeChallengeMethod.S256.toString())
            .field("response_type", "code")
            .field("nonce", "42")
            .field("scope", "urn:telematik:given_name openid")
            .field("acr_values", "gematik-ehealth-loa-high")
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .asString();
    assertThat(respMsg3.getStatus()).isEqualTo(HttpStatus.CREATED);

    final String requestUri =
        ((JsonObject) JsonParser.parseString(respMsg3.getBody())).get("request_uri").getAsString();

    Unirest.config().reset().followRedirects(false);
    final HttpResponse<String> respMsg7 =
        Unirest.get(testHostUrl + FED_AUTH_ENDPOINT)
            .queryString("request_uri", requestUri)
            .queryString("client_id", testHostUrl)
            .asString();

    assertThat(respMsg7.getStatus()).isEqualTo(HttpStatus.OK);
  }

  /*
   *  message nr.2 ... message nr.7
   * do auto registration and send invalid authorization request
   */
  @Test
  void authRequest_invalidParameter() {

    Mockito.doNothing()
        .when(entityStatementRpService)
        .doAutoregistration(testHostUrl, testHostUrl + "/AS", "urn:telematik:given_name openid");

    final HttpResponse<String> respMsg3 =
        Unirest.post(testHostUrl + FEDIDP_PAR_AUTH_ENDPOINT)
            .field("client_id", testHostUrl)
            .field("state", "state_Fachdienst")
            .field("redirect_uri", testHostUrl + "/AS")
            .field("code_challenge", "P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk")
            .field("code_challenge_method", CodeChallengeMethod.S256.toString())
            .field("response_type", "code")
            .field("nonce", "42")
            .field("scope", "urn:telematik:given_name openid")
            .field("acr_values", "gematik-ehealth-loa-high")
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .asString();
    assertThat(respMsg3.getStatus()).isEqualTo(HttpStatus.CREATED);

    final String requestUri =
        ((JsonObject) JsonParser.parseString(respMsg3.getBody())).get("request_uri").getAsString();

    Unirest.config().reset().followRedirects(false);

    // variant invalid request_uri
    final HttpResponse<String> respMsg7_a =
        Unirest.get(testHostUrl + FED_AUTH_ENDPOINT)
            .queryString("request_uri", "InvalidRequestUri")
            .queryString("client_id", testHostUrl)
            .asString();
    assertThat(respMsg7_a.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST);

    // variant invalid client_id
    final HttpResponse<String> respMsg7_b =
        Unirest.get(testHostUrl + FED_AUTH_ENDPOINT)
            .queryString("request_uri", requestUri)
            .queryString("client_id", "InvalidClientId")
            .asString();
    assertThat(respMsg7_b.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
  }

  @Test
  void parRequest_missingParameterResponseType_ResponseStatus_BAD_REQUEST() {
    final HttpResponse<String> resp =
        Unirest.post(testHostUrl + FEDIDP_PAR_AUTH_ENDPOINT)
            .field("client_id", testHostUrl)
            .field("client_id", testHostUrl)
            .field("state", "state_Fachdienst")
            .field("redirect_uri", testHostUrl + "/AS")
            .field("code_challenge", "P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk")
            .field("code_challenge_method", CodeChallengeMethod.S256.toString())
            .field("nonce", "42")
            .field("scope", "urn:telematik:given_name openid")
            .field("acr_values", "gematik-ehealth-loa-high")
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .asString();
    assertThat(resp.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
  }

  @Test
  void parRequest_InvalidGetOnPostMapping_ResponseStatus_BAD_REQUEST() {
    final HttpResponse<String> resp =
        Unirest.get(testHostUrl + FEDIDP_PAR_AUTH_ENDPOINT)
            .queryString("client_id", testHostUrl)
            .queryString("state", "state_Fachdienst")
            .queryString("redirect_uri", testHostUrl + "/AS")
            .queryString("code_challenge", "P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk")
            .queryString("code_challenge_method", CodeChallengeMethod.S256.toString())
            .queryString("response_type", "code")
            .queryString("nonce", "42")
            .queryString("scope", "urn:telematik:given_name openid")
            .queryString("acr_values", "gematik-ehealth-loa-high")
            .asString();
    assertThat(resp.getStatus()).isEqualTo(HttpStatus.METHOD_NOT_ALLOWED);
  }

  /************************** FEDIDP AUTH_ENDPOINT *****************/
  @Test
  void authRequest_invalidRequestUri_ResponseStatus_BAD_REQUEST() {
    final HttpResponse<String> resp =
        Unirest.get(testHostUrl + FED_AUTH_ENDPOINT)
            .queryString("request_uri", "myInvalidRequestUri")
            .queryString("client_id", testHostUrl)
            .asString();
    assertThat(resp.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
  }

  @SneakyThrows
  @Test
  void parRequest_authRequestUriPar_claimsResponse_contains_httpStatus_200() {

    final String KEY_ID = "puk_fd_enc";
    // key from gra-server/src/main/resources/keys/gras-enc-pubkey.pem
    final String JWK_AS_STRING_PUK_FED_ENC =
        "{\"use\": \"enc\",\"kid\": \""
            + KEY_ID
            + "\",\"kty\": \"EC\",\"crv\": \"P-256\",\"x\":"
            + " \"NQLaWbuQDHgSHahqb9zxlDdiMCHXSgY0L9ql1k7BVUE\",\"y\":"
            + " \"_USgmqhlM3pvabkZ2SS_YE2Q57tTs6pK9cE_uZB-u3c\"}";

    Mockito.doNothing()
        .when(entityStatementRpService)
        .doAutoregistration(
            testHostUrl,
            testHostUrl + "/AS",
            "urn:telematik:given_name urn:telematik:versicherter openid");

    Mockito.doReturn(PublicJsonWebKey.Factory.newPublicJwk(JWK_AS_STRING_PUK_FED_ENC))
        .when(entityStatementRpService)
        .getRpEncKey(any());

    final String codeVerifier = ClientUtilities.generateCodeVerifier();
    final String redirectUri = testHostUrl + "/AS";
    final String fachdienstClientId = testHostUrl;

    final HttpResponse<String> respMsg3 =
        Unirest.post(testHostUrl + FEDIDP_PAR_AUTH_ENDPOINT)
            .field("client_id", fachdienstClientId)
            .field("state", "state_Fachdienst")
            .field("redirect_uri", redirectUri)
            .field("code_challenge", ClientUtilities.generateCodeChallenge(codeVerifier))
            .field("code_challenge_method", CodeChallengeMethod.S256.toString())
            .field("response_type", "code")
            .field("nonce", "42")
            .field("scope", "urn:telematik:given_name urn:telematik:versicherter openid")
            .field("acr_values", "gematik-ehealth-loa-high")
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .asString();

    final String requestUri =
        ((JsonObject) JsonParser.parseString(respMsg3.getBody())).get("request_uri").getAsString();

    Unirest.config().reset().followRedirects(false);
    final HttpResponse<String> respMsg6a =
        Unirest.get(testHostUrl + FED_AUTH_ENDPOINT)
            .queryString("request_uri", requestUri)
            .queryString("device_type", "unittest")
            .asString();

    assertThat(respMsg6a.getStatus()).isEqualTo(HttpStatus.OK);
    final ClaimsResponse claimsResponse =
        new ObjectMapper().readValue(respMsg6a.getBody(), ClaimsResponse.class);
    assertThat(claimsResponse).isNotNull();
    assertThat(claimsResponse.getRequestedClaims())
        .containsExactlyInAnyOrder(
            "urn:telematik:claims:profession",
            "urn:telematik:claims:id",
            "urn:telematik:claims:organization",
            "urn:telematik:claims:given_name");
  }

  @SneakyThrows
  @Test
  void request_uri_expired_httpStatus_400() {

    final String KEY_ID = "puk_fd_enc";
    // key from gra-server/src/main/resources/keys/gras-enc-pubkey.pem
    final String JWK_AS_STRING_PUK_FED_ENC =
        "{\"use\": \"enc\",\"kid\": \""
            + KEY_ID
            + "\",\"kty\": \"EC\",\"crv\": \"P-256\",\"x\":"
            + " \"NQLaWbuQDHgSHahqb9zxlDdiMCHXSgY0L9ql1k7BVUE\",\"y\":"
            + " \"_USgmqhlM3pvabkZ2SS_YE2Q57tTs6pK9cE_uZB-u3c\"}";

    Mockito.doNothing()
        .when(entityStatementRpService)
        .doAutoregistration(
            testHostUrl,
            testHostUrl + "/AS",
            "urn:telematik:given_name urn:telematik:versicherter openid");

    Mockito.doReturn(PublicJsonWebKey.Factory.newPublicJwk(JWK_AS_STRING_PUK_FED_ENC))
        .when(entityStatementRpService)
        .getRpEncKey(any());

    final String codeVerifier = ClientUtilities.generateCodeVerifier();
    final String redirectUri = testHostUrl + "/AS";
    final String fachdienstClientId = testHostUrl;

    final HttpResponse<String> respMsg3 =
        Unirest.post(testHostUrl + FEDIDP_PAR_AUTH_ENDPOINT)
            .field("client_id", fachdienstClientId)
            .field("state", "state_Fachdienst")
            .field("redirect_uri", redirectUri)
            .field("code_challenge", ClientUtilities.generateCodeChallenge(codeVerifier))
            .field("code_challenge_method", CodeChallengeMethod.S256.toString())
            .field("response_type", "code")
            .field("nonce", "42")
            .field("scope", "urn:telematik:given_name urn:telematik:versicherter openid")
            .field("acr_values", "gematik-ehealth-loa-high")
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .asString();

    final String requestUri =
        ((JsonObject) JsonParser.parseString(respMsg3.getBody())).get("request_uri").getAsString();

    waitForSeconds(gsiConfiguration.getRequestUriTTL() + 2);

    Unirest.config().reset().followRedirects(false);
    final HttpResponse<String> respMsg6a =
        Unirest.get(testHostUrl + FED_AUTH_ENDPOINT)
            .queryString("request_uri", requestUri)
            .queryString("device_type", "unittest")
            .asString();

    assertThat(respMsg6a.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
  }

  /************************** FEDIDP_TOKEN_ENDPOINT *****************/
  @Test
  void tokenRequest_invalidCode_ResponseStatus_BAD_REQUEST() {
    final HttpResponse<JsonNode> httpResponse =
        Unirest.post(testHostUrl + TOKEN_ENDPOINT)
            .field("grant_type", "authorization_code")
            .field("code", "DUMMY_CODE")
            .field("code_verifier", "DUMMY_CODE_VERIFIER")
            .field("client_id", "https://DUMMY_CLIENT.de")
            .field("redirect_uri", "DUMMY_REDIRECT_URI")
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
            .asJson();
    assertThat(httpResponse.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
  }

  @Test
  void tokenRequest_invalidGrantType_ResponseStatus_BAD_REQUEST() {
    final HttpResponse<JsonNode> httpResponse =
        Unirest.post(testHostUrl + TOKEN_ENDPOINT)
            .field("grant_type", "auth")
            .field("code", "DUMMY_CODE")
            .field("code_verifier", "DUMMY_CODE_VERIFIER")
            .field("client_id", "https://DUMMY_CLIENT.de")
            .field("redirect_uri", "DUMMY_REDIRECT_URI")
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
            .asJson();
    assertThat(httpResponse.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
  }

  @Test
  void tokenRequest_InvalidGetOnPostMapping_ResponseStatus_BAD_REQUEST() {
    final HttpResponse<String> resp =
        Unirest.get(testHostUrl + TOKEN_ENDPOINT)
            .queryString("client_id", testHostUrl)
            .queryString("grant_type", "state_Fachdienst")
            .queryString("redirect_uri", testHostUrl + "/AS")
            .queryString("code_verifier", "P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk")
            .queryString("code", CodeChallengeMethod.S256.toString())
            .queryString("response_type", "code")
            .asString();
    assertThat(resp.getStatus()).isEqualTo(HttpStatus.METHOD_NOT_ALLOWED);
  }

  @SneakyThrows
  @Test
  void parRequest_authRequestUriPar_tokenResponse_contains_httpStatus_200() {

    final String KEY_ID = "puk_fd_enc";
    // key from gra-server/src/main/resources/keys/gras-enc-pubkey.pem
    final String JWK_AS_STRING_PUK_FED_ENC =
        "{\"use\": \"enc\",\"kid\": \""
            + KEY_ID
            + "\",\"kty\": \"EC\",\"crv\": \"P-256\",\"x\":"
            + " \"NQLaWbuQDHgSHahqb9zxlDdiMCHXSgY0L9ql1k7BVUE\",\"y\":"
            + " \"_USgmqhlM3pvabkZ2SS_YE2Q57tTs6pK9cE_uZB-u3c\"}";

    Mockito.doNothing()
        .when(entityStatementRpService)
        .doAutoregistration(testHostUrl, testHostUrl + "/AS", "urn:telematik:given_name openid");

    Mockito.doReturn(PublicJsonWebKey.Factory.newPublicJwk(JWK_AS_STRING_PUK_FED_ENC))
        .when(entityStatementRpService)
        .getRpEncKey(any());

    final String codeVerifier = ClientUtilities.generateCodeVerifier();
    final String redirectUri = testHostUrl + "/AS";
    final String fachdienstClientId = testHostUrl;

    final HttpResponse<String> respMsg3 =
        Unirest.post(testHostUrl + FEDIDP_PAR_AUTH_ENDPOINT)
            .field("client_id", fachdienstClientId)
            .field("state", "state_Fachdienst")
            .field("redirect_uri", redirectUri)
            .field("code_challenge", ClientUtilities.generateCodeChallenge(codeVerifier))
            .field("code_challenge_method", CodeChallengeMethod.S256.toString())
            .field("response_type", "code")
            .field("nonce", "42")
            .field("scope", "urn:telematik:given_name openid")
            .field("acr_values", "gematik-ehealth-loa-high")
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .asString();
    assertThat(respMsg3.getStatus()).isEqualTo(HttpStatus.CREATED);

    final String requestUri =
        ((JsonObject) JsonParser.parseString(respMsg3.getBody())).get("request_uri").getAsString();

    Unirest.config().reset().followRedirects(false);
    final HttpResponse<String> respMsg7 =
        Unirest.get(testHostUrl + FED_AUTH_ENDPOINT)
            .queryString("request_uri", requestUri)
            .queryString("user_id", "12345678")
            .asString();

    assertThat(respMsg7.getStatus()).isEqualTo(HttpStatus.FOUND);
    final String code =
        UriUtils.extractParameterValue(respMsg7.getHeaders().get("Location").get(0), "code");

    final HttpResponse<JsonNode> httpResponse =
        Unirest.post(testHostUrl + TOKEN_ENDPOINT)
            .field("grant_type", "authorization_code")
            .field("code", code)
            .field("code_verifier", codeVerifier)
            .field("client_id", fachdienstClientId)
            .field("redirect_uri", redirectUri)
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .header(HttpHeaders.USER_AGENT, "IdP-Client")
            .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
            .asJson();
    assertThat(httpResponse.getStatus()).isEqualTo(HttpStatus.OK);

    final String idTokenEncrypted = httpResponse.getBody().getObject().getString("id_token");
    final IdpJwe idpJwe = new IdpJwe(idTokenEncrypted);

    // verify that token is encrypted and check kid
    assertThat(idpJwe.extractHeaderClaims()).containsEntry("kid", KEY_ID);
  }

  @SneakyThrows
  @Test
  void parRequest_authRequestUriPar_userConsent_tokenResponse_contains_httpStatus_200() {

    final String KEY_ID = "puk_fd_enc";
    // key from gra-server/src/main/resources/keys/gras-enc-pubkey.pem
    final String JWK_AS_STRING_PUK_FED_ENC =
        "{\"use\": \"enc\",\"kid\": \""
            + KEY_ID
            + "\",\"kty\": \"EC\",\"crv\": \"P-256\",\"x\":"
            + " \"NQLaWbuQDHgSHahqb9zxlDdiMCHXSgY0L9ql1k7BVUE\",\"y\":"
            + " \"_USgmqhlM3pvabkZ2SS_YE2Q57tTs6pK9cE_uZB-u3c\"}";

    Mockito.doNothing()
        .when(entityStatementRpService)
        .doAutoregistration(testHostUrl, testHostUrl + "/AS", "urn:telematik:versicherter openid");

    Mockito.doReturn(PublicJsonWebKey.Factory.newPublicJwk(JWK_AS_STRING_PUK_FED_ENC))
        .when(entityStatementRpService)
        .getRpEncKey(any());

    final String codeVerifier = ClientUtilities.generateCodeVerifier();
    final String redirectUri = testHostUrl + "/AS";
    final String fachdienstClientId = testHostUrl;

    final HttpResponse<String> respMsg3 =
        Unirest.post(testHostUrl + FEDIDP_PAR_AUTH_ENDPOINT)
            .field("client_id", fachdienstClientId)
            .field("state", "state_Fachdienst")
            .field("redirect_uri", redirectUri)
            .field("code_challenge", ClientUtilities.generateCodeChallenge(codeVerifier))
            .field("code_challenge_method", CodeChallengeMethod.S256.toString())
            .field("response_type", "code")
            .field("nonce", "42")
            .field("scope", "urn:telematik:versicherter openid")
            .field("acr_values", "gematik-ehealth-loa-high")
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .asString();
    assertThat(respMsg3.getStatus()).isEqualTo(HttpStatus.CREATED);

    final String requestUri =
        ((JsonObject) JsonParser.parseString(respMsg3.getBody())).get("request_uri").getAsString();

    Unirest.config().reset().followRedirects(false);
    final HttpResponse<String> respMsg6a =
        Unirest.get(testHostUrl + FED_AUTH_ENDPOINT)
            .queryString("request_uri", requestUri)
            .queryString("device_type", "unittest")
            .asString();

    final HttpResponse<String> respMsg7 =
        Unirest.get(testHostUrl + FED_AUTH_ENDPOINT)
            .queryString("request_uri", requestUri)
            .queryString("user_id", "12345678")
            .queryString(
                "selected_claims", "urn:telematik:claims:profession urn:telematik:claims:id")
            .asString();

    assertThat(respMsg7.getStatus()).isEqualTo(HttpStatus.FOUND);
    final String code =
        UriUtils.extractParameterValue(respMsg7.getHeaders().get("Location").get(0), "code");

    final HttpResponse<JsonNode> httpResponse =
        Unirest.post(testHostUrl + TOKEN_ENDPOINT)
            .field("grant_type", "authorization_code")
            .field("code", code)
            .field("code_verifier", codeVerifier)
            .field("client_id", fachdienstClientId)
            .field("redirect_uri", redirectUri)
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .header(HttpHeaders.USER_AGENT, "IdP-Client")
            .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
            .asJson();
    assertThat(httpResponse.getStatus()).isEqualTo(HttpStatus.OK);

    final String idTokenEncrypted = httpResponse.getBody().getObject().getString("id_token");
    final IdpJwe idpJwe = new IdpJwe(idTokenEncrypted);

    // verify that token is encrypted and check kid
    assertThat(idpJwe.extractHeaderClaims()).containsEntry("kid", KEY_ID);
  }

  @Test
  void parRequest_validAmr_httpsStatus_201() {
    final String codeVerifier = ClientUtilities.generateCodeVerifier();
    final String redirectUri = testHostUrl + "/AS";
    final String fachdienstClientId = testHostUrl;
    final HttpResponse<String> respMsg3 =
        Unirest.post(testHostUrl + FEDIDP_PAR_AUTH_ENDPOINT)
            .field("client_id", fachdienstClientId)
            .field("state", "state_Fachdienst")
            .field("redirect_uri", redirectUri)
            .field("code_challenge", ClientUtilities.generateCodeChallenge(codeVerifier))
            .field("code_challenge_method", CodeChallengeMethod.S256.toString())
            .field("response_type", "code")
            .field("nonce", "42")
            .field("scope", "urn:telematik:versicherter openid")
            .field("acr_values", "gematik-ehealth-loa-high")
            .field("amr", "urn:telematik:auth:eGK")
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .asString();
    assertThat(respMsg3.getStatus()).isEqualTo(HttpStatus.CREATED);
  }

  @Test
  void parRequest_invalidAmr_httpsStatus_400_message() {
    final String codeVerifier = ClientUtilities.generateCodeVerifier();
    final String redirectUri = testHostUrl + "/AS";
    final String fachdienstClientId = testHostUrl;
    final HttpResponse<JsonNode> respMsg3 =
        Unirest.post(testHostUrl + FEDIDP_PAR_AUTH_ENDPOINT)
            .field("client_id", fachdienstClientId)
            .field("state", "state_Fachdienst")
            .field("redirect_uri", redirectUri)
            .field("code_challenge", ClientUtilities.generateCodeChallenge(codeVerifier))
            .field("code_challenge_method", CodeChallengeMethod.S256.toString())
            .field("response_type", "code")
            .field("nonce", "42")
            .field("scope", "urn:telematik:versicherter openid")
            .field("acr_values", "gematik-ehealth-loa-high")
            .field("amr", "urn:telematik:auth:invalid")
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .asJson();
    assertThat(respMsg3.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
    assertThat(respMsg3.getBody().getObject().getString("error_description"))
        .contains("amr: must match");
  }

  @Test
  void parRequest_prompt_httpsStatus_201() {
    final String codeVerifier = ClientUtilities.generateCodeVerifier();
    final String redirectUri = testHostUrl + "/AS";
    final String fachdienstClientId = testHostUrl;
    final HttpResponse<JsonNode> respMsg3 =
        Unirest.post(testHostUrl + FEDIDP_PAR_AUTH_ENDPOINT)
            .field("client_id", fachdienstClientId)
            .field("state", "state_Fachdienst")
            .field("redirect_uri", redirectUri)
            .field("code_challenge", ClientUtilities.generateCodeChallenge(codeVerifier))
            .field("code_challenge_method", CodeChallengeMethod.S256.toString())
            .field("response_type", "code")
            .field("nonce", "42")
            .field("scope", "urn:telematik:versicherter openid")
            .field("acr_values", "gematik-ehealth-loa-high")
            .field("prompt", "login")
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .asJson();
    assertThat(respMsg3.getStatus()).isEqualTo(HttpStatus.CREATED);
  }

  @Test
  void parRequest_max_age_httpsStatus_201() {
    final String codeVerifier = ClientUtilities.generateCodeVerifier();
    final String redirectUri = testHostUrl + "/AS";
    final String fachdienstClientId = testHostUrl;
    final HttpResponse<JsonNode> respMsg3 =
        Unirest.post(testHostUrl + FEDIDP_PAR_AUTH_ENDPOINT)
            .field("client_id", fachdienstClientId)
            .field("state", "state_Fachdienst")
            .field("redirect_uri", redirectUri)
            .field("code_challenge", ClientUtilities.generateCodeChallenge(codeVerifier))
            .field("code_challenge_method", CodeChallengeMethod.S256.toString())
            .field("response_type", "code")
            .field("nonce", "42")
            .field("scope", "urn:telematik:versicherter openid")
            .field("acr_values", "gematik-ehealth-loa-high")
            .field("max_age", "0")
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .asJson();
    assertThat(respMsg3.getStatus()).isEqualTo(HttpStatus.CREATED);
  }

  @SneakyThrows
  @Test
  void parRequest_authRequestUriPar_invalidUserConsent_httpStatus_400() {

    final String KEY_ID = "puk_fd_enc";
    // key from gra-server/src/main/resources/keys/gras-enc-pubkey.pem
    final String JWK_AS_STRING_PUK_FED_ENC =
        "{\"use\": \"enc\",\"kid\": \""
            + KEY_ID
            + "\",\"kty\": \"EC\",\"crv\": \"P-256\",\"x\":"
            + " \"NQLaWbuQDHgSHahqb9zxlDdiMCHXSgY0L9ql1k7BVUE\",\"y\":"
            + " \"_USgmqhlM3pvabkZ2SS_YE2Q57tTs6pK9cE_uZB-u3c\"}";

    Mockito.doNothing()
        .when(entityStatementRpService)
        .doAutoregistration(testHostUrl, testHostUrl + "/AS", "urn:telematik:versicherter openid");

    Mockito.doReturn(PublicJsonWebKey.Factory.newPublicJwk(JWK_AS_STRING_PUK_FED_ENC))
        .when(entityStatementRpService)
        .getRpEncKey(any());

    final String codeVerifier = ClientUtilities.generateCodeVerifier();
    final String redirectUri = testHostUrl + "/AS";
    final String fachdienstClientId = testHostUrl;

    final HttpResponse<String> respMsg3 =
        Unirest.post(testHostUrl + FEDIDP_PAR_AUTH_ENDPOINT)
            .field("client_id", fachdienstClientId)
            .field("state", "state_Fachdienst")
            .field("redirect_uri", redirectUri)
            .field("code_challenge", ClientUtilities.generateCodeChallenge(codeVerifier))
            .field("code_challenge_method", CodeChallengeMethod.S256.toString())
            .field("response_type", "code")
            .field("nonce", "42")
            .field("scope", "urn:telematik:versicherter openid")
            .field("acr_values", "gematik-ehealth-loa-high")
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .asString();
    assertThat(respMsg3.getStatus()).isEqualTo(HttpStatus.CREATED);

    final String requestUri =
        ((JsonObject) JsonParser.parseString(respMsg3.getBody())).get("request_uri").getAsString();

    Unirest.get(testHostUrl + FED_AUTH_ENDPOINT)
        .queryString("request_uri", requestUri)
        .queryString("device_type", "unittest")
        .asString();

    final HttpResponse<JsonNode> respMsg7 =
        Unirest.get(testHostUrl + FED_AUTH_ENDPOINT)
            .queryString("request_uri", requestUri)
            .queryString("user_id", "12345678")
            .queryString("selected_claims", "urn:telematik:claims:given_name")
            .asJson();

    assertThat(respMsg7.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
    assertThat(respMsg7.getBody().toString()).contains("selected claims exceed scopes in PAR");
  }

  /** Increase Test coverage of Landing page endpoint */
  @Test
  void parRequest_authRequestUriPar_invalidClientId_httpStatus_400() {
    Mockito.doNothing()
        .when(entityStatementRpService)
        .doAutoregistration(testHostUrl, testHostUrl + "/AS", "urn:telematik:given_name openid");

    final String codeVerifier = ClientUtilities.generateCodeVerifier();
    final String redirectUri = testHostUrl + "/AS";

    final HttpResponse<String> respMsg3 =
        Unirest.post(testHostUrl + FEDIDP_PAR_AUTH_ENDPOINT)
            .field("client_id", "invalidClientId")
            .field("state", "state_Fachdienst")
            .field("redirect_uri", redirectUri)
            .field("code_challenge", ClientUtilities.generateCodeChallenge(codeVerifier))
            .field("code_challenge_method", CodeChallengeMethod.S256.toString())
            .field("response_type", "code")
            .field("nonce", "42")
            .field("scope", "urn:telematik:given_name openid")
            .field("acr_values", "gematik-ehealth-loa-high")
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .asString();
    assertThat(respMsg3.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
  }

  /**
   * ClientID may contain just http and not https. This should work as well for local development
   * environment.
   */
  @Test
  void parRequest_authRequestUriPar_ClientIdHttp_httpStatus_201() {
    Mockito.doNothing()
        .when(entityStatementRpService)
        .doAutoregistration(testHostUrl, testHostUrl + "/AS", "urn:telematik:given_name openid");

    final String codeVerifier = ClientUtilities.generateCodeVerifier();
    final String redirectUri = testHostUrl + "/AS";

    final HttpResponse<String> respMsg3 =
        Unirest.post(testHostUrl + FEDIDP_PAR_AUTH_ENDPOINT)
            .field("client_id", "http://127.0.0.1:8084")
            .field("state", "state_Fachdienst")
            .field("redirect_uri", redirectUri)
            .field("code_challenge", ClientUtilities.generateCodeChallenge(codeVerifier))
            .field("code_challenge_method", CodeChallengeMethod.S256.toString())
            .field("response_type", "code")
            .field("nonce", "42")
            .field("scope", "urn:telematik:given_name openid")
            .field("acr_values", "gematik-ehealth-loa-high")
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .asString();
    assertThat(respMsg3.getStatus()).isEqualTo(HttpStatus.CREATED);
  }

  /** Increase Test coverage of Token endpoint */
  @Test
  void
      parRequest_authRequestUriPar_tokenRequest_invalidRedirectUri_invalidCodeVerifier_contains_httpStatus_400() {
    Mockito.doNothing()
        .when(entityStatementRpService)
        .doAutoregistration(testHostUrl, testHostUrl + "/AS", "urn:telematik:given_name openid");

    final String codeVerifier = ClientUtilities.generateCodeVerifier();
    final String redirectUri = testHostUrl + "/AS";
    final String fachdienstClientId = testHostUrl;

    final HttpResponse<String> respMsg3 =
        Unirest.post(testHostUrl + FEDIDP_PAR_AUTH_ENDPOINT)
            .field("client_id", fachdienstClientId)
            .field("state", "state_Fachdienst")
            .field("redirect_uri", redirectUri)
            .field("code_challenge", ClientUtilities.generateCodeChallenge(codeVerifier))
            .field("code_challenge_method", CodeChallengeMethod.S256.toString())
            .field("response_type", "code")
            .field("nonce", "42")
            .field("scope", "urn:telematik:given_name openid")
            .field("acr_values", "gematik-ehealth-loa-high")
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .asString();
    assertThat(respMsg3.getStatus()).isEqualTo(HttpStatus.CREATED);

    final String requestUri =
        ((JsonObject) JsonParser.parseString(respMsg3.getBody())).get("request_uri").getAsString();

    Unirest.config().reset().followRedirects(false);
    final HttpResponse<String> respMsg7 =
        Unirest.get(testHostUrl + FED_AUTH_ENDPOINT)
            .queryString("request_uri", requestUri)
            .queryString("user_id", "12345678")
            .asString();

    assertThat(respMsg7.getStatus()).isEqualTo(HttpStatus.FOUND);
    final String code =
        UriUtils.extractParameterValue(respMsg7.getHeaders().get("Location").get(0), "code");

    final HttpResponse<JsonNode> httpResponse1 =
        Unirest.post(testHostUrl + TOKEN_ENDPOINT)
            .field("grant_type", "authorization_code")
            .field("code", code)
            .field("code_verifier", "invalidCodeVerifier")
            .field("client_id", fachdienstClientId)
            .field("redirect_uri", redirectUri)
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .header(HttpHeaders.USER_AGENT, "IdP-Client")
            .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
            .asJson();
    assertThat(httpResponse1.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST);

    final HttpResponse<JsonNode> httpResponse2 =
        Unirest.post(testHostUrl + TOKEN_ENDPOINT)
            .field("grant_type", "authorization_code")
            .field("code", code)
            .field("code_verifier", codeVerifier)
            .field("client_id", fachdienstClientId)
            .field("redirect_uri", "invalidRedirectUri")
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .header(HttpHeaders.USER_AGENT, "IdP-Client")
            .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
            .asJson();
    assertThat(httpResponse2.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
  }

  @SneakyThrows
  @Test
  void parRequest_tlsCertificateHeader() {

    Mockito.doReturn(certFromEntityStmtRpService)
        .when(entityStatementRpService)
        .getRpTlsClientCert(any());

    final String codeVerifier = ClientUtilities.generateCodeVerifier();
    final String redirectUri = testHostUrl + "/AS";
    final String fachdienstClientId = testHostUrl;
    final HttpResponse<String> respMsg3 =
        Unirest.post(testHostUrl + FEDIDP_PAR_AUTH_ENDPOINT)
            .field("client_id", fachdienstClientId)
            .field("state", "state_Fachdienst")
            .field("redirect_uri", redirectUri)
            .field("code_challenge", ClientUtilities.generateCodeChallenge(codeVerifier))
            .field("code_challenge_method", CodeChallengeMethod.S256.toString())
            .field("response_type", "code")
            .field("nonce", "42")
            .field("scope", "urn:telematik:versicherter openid")
            .field("acr_values", "gematik-ehealth-loa-high")
            .header(TLS_CLIENT_CERT_HEADER_NAME, certFromRequest)
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .asString();
    assertThat(respMsg3.getStatus()).isEqualTo(HttpStatus.CREATED);
  }

  @SneakyThrows
  @Test
  void parRequest_invalidTlsCertificateHeader_anyString() {

    Mockito.doReturn(certFromEntityStmtRpService)
        .when(entityStatementRpService)
        .getRpTlsClientCert(any());

    final String codeVerifier = ClientUtilities.generateCodeVerifier();
    final String redirectUri = testHostUrl + "/AS";
    final String fachdienstClientId = testHostUrl;
    final HttpResponse<JsonNode> respMsg3 =
        Unirest.post(testHostUrl + FEDIDP_PAR_AUTH_ENDPOINT)
            .field("client_id", fachdienstClientId)
            .field("state", "state_Fachdienst")
            .field("redirect_uri", redirectUri)
            .field("code_challenge", ClientUtilities.generateCodeChallenge(codeVerifier))
            .field("code_challenge_method", CodeChallengeMethod.S256.toString())
            .field("response_type", "code")
            .field("nonce", "42")
            .field("scope", "urn:telematik:versicherter openid")
            .field("acr_values", "gematik-ehealth-loa-high")
            .header(TLS_CLIENT_CERT_HEADER_NAME, "AnyInvalidString")
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .asJson();
    assertThat(respMsg3.getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED);
    assertThat(respMsg3.getBody().getObject().getString("error"))
        .isEqualTo(UNAUTHORIZED_CLIENT.getSerializationValue());
    assertThat(respMsg3.getBody().getObject().getString("error_description"))
        .contains("client certificate in tls handshake is not a valid x509 certificate");
  }

  @SneakyThrows
  @Test
  void parRequest_certInHeaderAndInEntityStatementDontMatch() {

    Mockito.doReturn(otherCert).when(entityStatementRpService).getRpTlsClientCert(any());

    final String codeVerifier = ClientUtilities.generateCodeVerifier();
    final String redirectUri = testHostUrl + "/AS";
    final String fachdienstClientId = testHostUrl;
    final HttpResponse<JsonNode> respMsg3 =
        Unirest.post(testHostUrl + FEDIDP_PAR_AUTH_ENDPOINT)
            .field("client_id", fachdienstClientId)
            .field("state", "state_Fachdienst")
            .field("redirect_uri", redirectUri)
            .field("code_challenge", ClientUtilities.generateCodeChallenge(codeVerifier))
            .field("code_challenge_method", CodeChallengeMethod.S256.toString())
            .field("response_type", "code")
            .field("nonce", "42")
            .field("scope", "urn:telematik:versicherter openid")
            .field("acr_values", "gematik-ehealth-loa-high")
            .header(TLS_CLIENT_CERT_HEADER_NAME, certFromRequest)
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .asJson();
    assertThat(respMsg3.getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED);
    assertThat(respMsg3.getBody().getObject().getString("error"))
        .isEqualTo(UNAUTHORIZED_CLIENT.getSerializationValue());
    assertThat(respMsg3.getBody().getObject().getString("error_description"))
        .contains(
            "client certificate in tls handshake does not match certificate in entity"
                + " statement/signed_jwks");
  }

  @SneakyThrows
  @Test
  void tokenRequest_tlsCertificateHeader() {
    final String KEY_ID = "puk_fd_enc";
    // key from gra-server/src/main/resources/keys/gras-enc-pubkey.pem
    final String JWK_AS_STRING_PUK_FED_ENC =
        "{\"use\": \"enc\",\"kid\": \""
            + KEY_ID
            + "\",\"kty\": \"EC\",\"crv\": \"P-256\",\"x\":"
            + " \"NQLaWbuQDHgSHahqb9zxlDdiMCHXSgY0L9ql1k7BVUE\",\"y\":"
            + " \"_USgmqhlM3pvabkZ2SS_YE2Q57tTs6pK9cE_uZB-u3c\"}";

    Mockito.doNothing()
        .when(entityStatementRpService)
        .doAutoregistration(testHostUrl, testHostUrl + "/AS", "urn:telematik:versicherter openid");

    Mockito.doReturn(PublicJsonWebKey.Factory.newPublicJwk(JWK_AS_STRING_PUK_FED_ENC))
        .when(entityStatementRpService)
        .getRpEncKey(any());

    Mockito.doReturn(certFromEntityStmtRpService)
        .when(entityStatementRpService)
        .getRpTlsClientCert(any());

    final String codeVerifier = ClientUtilities.generateCodeVerifier();
    final String redirectUri = testHostUrl + "/AS";
    final String fachdienstClientId = testHostUrl;
    final HttpResponse<String> respMsg3 =
        Unirest.post(testHostUrl + FEDIDP_PAR_AUTH_ENDPOINT)
            .field("client_id", fachdienstClientId)
            .field("state", "state_Fachdienst")
            .field("redirect_uri", redirectUri)
            .field("code_challenge", ClientUtilities.generateCodeChallenge(codeVerifier))
            .field("code_challenge_method", CodeChallengeMethod.S256.toString())
            .field("response_type", "code")
            .field("nonce", "42")
            .field("scope", "urn:telematik:versicherter openid")
            .field("acr_values", "gematik-ehealth-loa-high")
            .header(TLS_CLIENT_CERT_HEADER_NAME, certFromRequest)
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .asString();
    assertThat(respMsg3.getStatus()).isEqualTo(HttpStatus.CREATED);
    final String requestUri =
        ((JsonObject) JsonParser.parseString(respMsg3.getBody())).get("request_uri").getAsString();

    Unirest.config().reset().followRedirects(false);
    final HttpResponse<String> respMsg7 =
        Unirest.get(testHostUrl + FED_AUTH_ENDPOINT)
            .queryString("request_uri", requestUri)
            .queryString("user_id", "12345678")
            .asString();

    assertThat(respMsg7.getStatus()).isEqualTo(HttpStatus.FOUND);

    final String code =
        UriUtils.extractParameterValue(respMsg7.getHeaders().get("Location").get(0), "code");

    final HttpResponse<JsonNode> httpResponse =
        Unirest.post(testHostUrl + TOKEN_ENDPOINT)
            .field("grant_type", "authorization_code")
            .field("code", code)
            .field("code_verifier", codeVerifier)
            .field("client_id", fachdienstClientId)
            .field("redirect_uri", redirectUri)
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .header(HttpHeaders.USER_AGENT, "IdP-Client")
            .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
            .header(TLS_CLIENT_CERT_HEADER_NAME, certFromRequest)
            .asJson();
    assertThat(httpResponse.getStatus()).isEqualTo(HttpStatus.OK);
  }

  private void waitForSeconds(final int seconds) {
    Awaitility.await()
        .atMost(seconds + 1, TimeUnit.SECONDS)
        .pollDelay(seconds, TimeUnit.SECONDS)
        .until(() -> true);
  }
}
