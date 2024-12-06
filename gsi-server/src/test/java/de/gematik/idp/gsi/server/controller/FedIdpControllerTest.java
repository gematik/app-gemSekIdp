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
import static de.gematik.idp.data.Oauth2ErrorCode.INVALID_REQUEST;
import static de.gematik.idp.data.Oauth2ErrorCode.UNAUTHORIZED_CLIENT;
import static de.gematik.idp.gsi.server.common.Constants.ENTITY_STMNT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2043;
import static de.gematik.idp.gsi.server.data.GsiConstants.ACR_HIGH;
import static de.gematik.idp.gsi.server.data.GsiConstants.FEDIDP_PAR_AUTH_ENDPOINT;
import static de.gematik.idp.gsi.server.data.GsiConstants.FED_SIGNED_JWKS_ENDPOINT;
import static de.gematik.idp.gsi.server.data.GsiConstants.TLS_CLIENT_CERT_HEADER_NAME;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.ArgumentMatchers.any;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.jayway.jsonpath.JsonPath;
import de.gematik.idp.IdpConstants;
import de.gematik.idp.authentication.UriUtils;
import de.gematik.idp.field.ClientUtilities;
import de.gematik.idp.field.CodeChallengeMethod;
import de.gematik.idp.gsi.server.GsiServer;
import de.gematik.idp.gsi.server.configuration.GsiConfiguration;
import de.gematik.idp.gsi.server.data.ClaimsResponse;
import de.gematik.idp.gsi.server.data.RpToken;
import de.gematik.idp.gsi.server.exceptions.GsiException;
import de.gematik.idp.gsi.server.services.EntityStatementRpReader;
import de.gematik.idp.gsi.server.services.RequestValidator;
import de.gematik.idp.gsi.server.services.TokenRepositoryRp;
import de.gematik.idp.token.IdpJwe;
import de.gematik.idp.token.JsonWebToken;
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
import org.awaitility.Awaitility;
import org.jose4j.jwk.PublicJsonWebKey;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

@Slf4j
@SpringBootTest(classes = GsiServer.class, webEnvironment = WebEnvironment.RANDOM_PORT)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@ExtendWith(SpringExtension.class)
class FedIdpControllerTest {

  private static final List<String> OPENID_PROVIDER_CLAIMS =
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

  @DynamicPropertySource
  static void dynamicProperties(final DynamicPropertyRegistry registry) {
    registry.add("gsi.requestUriTTL", () -> 5);
  }

  @Autowired private GsiConfiguration gsiConfiguration;

  private MockMvc mockMvc;
  @Autowired private WebApplicationContext context;
  @MockBean private TokenRepositoryRp rpTokenRepository;
  private static MockedStatic<RequestValidator> requestValidatorMockedStatic;
  private static MockedStatic<EntityStatementRpReader> esReaderMockedStatic;

  private String testHostUrl;
  @LocalServerPort private int serverPort;
  private String codeVerifier;
  private String redirectUri;
  private String fachdienstClientId;

  private static final RpToken VALID_RPTOKEN =
      new RpToken(new JsonWebToken(ENTITY_STMNT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2043));

  private HttpResponse<String> entityStatementResponseGood;
  private JsonWebToken entityStatement;
  private Map<String, Object> entityStatementbodyClaims;

  private HttpResponse<String> signedJwksResponseGood;
  private JsonWebToken signedJwks;

  private static final String CERT1_FROM_REQUEST =
      "-----BEGIN%20CERTIFICATE-----%0AMIIDszCCApugAwIBAgIUY%2FqefKABeWr36nT%2Brw9hJsbYFu8wDQYJKoZIhvcNAQEL%0ABQAwdjELMAkGA1UEBhMCREUxDzANBgNVBAgMBkJlcmxpbjEPMA0GA1UEBwwGQmVy%0AbGluMRkwFwYDVQQKDBBnZW1hdGlrVEVTVC1PTkxZMQ8wDQYDVQQLDAZQVCBJRE0x%0AGTAXBgNVBAMMEGZhZGlUbHNDbGllbnRSc2EwHhcNMjQwNjEzMDcxNjUyWhcNMjUw%0ANjEzMDcxNjUyWjB2MQswCQYDVQQGEwJERTEPMA0GA1UECAwGQmVybGluMQ8wDQYD%0AVQQHDAZCZXJsaW4xGTAXBgNVBAoMEGdlbWF0aWtURVNULU9OTFkxDzANBgNVBAsM%0ABlBUIElETTEZMBcGA1UEAwwQZmFkaVRsc0NsaWVudFJzYTCCASIwDQYJKoZIhvcN%0AAQEBBQADggEPADCCAQoCggEBAKiQaMTyY%2FlTTO9V4YJq7xsfN8l0%2BSqe2rRRasVU%0A8wenG8eohk99d1i5%2Fh08%2B%2BK1A5FX9GxgWh0RXGotpvbVvM7kzdOWxBJIK7j68R9g%0A%2F6B%2BKKO89rywLiJkxRT%2BOA4dusqocGDKmqFYZC1ntt2nSsSLlX3OuDC%2F1Thlhz2i%0AEGtweuYRL3zPeDXiegdyjRCY%2F9Xe%2FwaC4amuuJ5JkE5EsM0mL09kfkZCzdx8j2KK%0AqYTH2TYmiOG16CIVyZi9pE%2BKEHw95MIIcrzrO6QLWXcl7Y82rwVeeoUSicLBEydd%0A4YmsZ6pp%2BKGH0b9ycQO%2Bxs2uv79%2B5Zza9Q4OazEka4N0LyMCAwEAAaM5MDcwCQYD%0AVR0TBAIwADALBgNVHQ8EBAMCBeAwHQYDVR0OBBYEFMmogwgia7kONxur5UWBDX5g%0ABP0HMA0GCSqGSIb3DQEBCwUAA4IBAQAFK6nct1YVLMR6Tznh6ZrsvYs0UzCElUGM%0AnJtYaeCTgQPVKigQC4SPf%2FJp9qychooSbS7gbponndXgGIz8VFmt9y4d4q0uZKOr%0ALp7qcK%2BgQdvBts5TDZH20IiwW5b6VyGp%2Fos8fqR8WIt7fHdNz6Mu1fh2HsB4YjV9%0AxbbXTcKSzS6TROzh9bt2ubFX4ex56j6Mniy3DNF6zsW4kdh7naB%2FLfXvtH276Gj%2B%0AInhaF1sBLI8IIyQ5K2q2MJaly%2F8wiOys7FuG7duD1Lmh2kRO0FZkXsaQJmbZncUs%0A%2B4tgmnpEVgZ0FlKQ1BDAl0o0e7QbVRMiI2gjz7itOWFiUXvnMNIA%0A-----END%20CERTIFICATE-----%0A";

  private static final String KEY_ID = "puk_fd_enc";

  @SneakyThrows
  @BeforeAll
  void setup() {
    testHostUrl = "http://localhost:" + serverPort;
    codeVerifier = ClientUtilities.generateCodeVerifier();
    redirectUri = testHostUrl + "/AS";
    fachdienstClientId = testHostUrl;

    entityStatementResponseGood = retrieveEntityStatement();
    assertThat(entityStatementResponseGood.getStatus()).isEqualTo(HttpStatus.OK);
    entityStatement = new JsonWebToken(entityStatementResponseGood.getBody());
    entityStatementbodyClaims = entityStatement.extractBodyClaims();

    signedJwksResponseGood = retrieveSignedJwks();
    signedJwks = new JsonWebToken(signedJwksResponseGood.getBody());
  }

  @SneakyThrows
  @BeforeEach
  void init(final TestInfo testInfo) {
    mockMvc = MockMvcBuilders.webAppContextSetup(context).build();
    log.info("START UNIT TEST: {}", testInfo.getDisplayName());

    Mockito.doReturn(VALID_RPTOKEN).when(rpTokenRepository).getEntityStatementRp(any());

    requestValidatorMockedStatic = Mockito.mockStatic(RequestValidator.class);
    esReaderMockedStatic = Mockito.mockStatic(EntityStatementRpReader.class);

    // key from gra-server/src/main/resources/keys/gras-enc-pubkey.pem
    final String JWK_AS_STRING_PUK_FED_ENC =
        "{\"use\": \"enc\",\"kid\": \""
            + KEY_ID
            + "\",\"kty\": \"EC\",\"crv\": \"P-256\",\"x\":"
            + " \"NQLaWbuQDHgSHahqb9zxlDdiMCHXSgY0L9ql1k7BVUE\",\"y\":"
            + " \"_USgmqhlM3pvabkZ2SS_YE2Q57tTs6pK9cE_uZB-u3c\"}";

    esReaderMockedStatic
        .when(() -> EntityStatementRpReader.getRpEncKey(any()))
        .thenReturn(PublicJsonWebKey.Factory.newPublicJwk(JWK_AS_STRING_PUK_FED_ENC));
  }

  @AfterEach
  void tearDown() {
    requestValidatorMockedStatic.close();
    esReaderMockedStatic.close();
  }

  /************************** ENTITY_STATEMENT_ENDPOINT *****************/

  @SuppressWarnings("unchecked")
  private Map<String, Object> getInnerClaimMap(
      final Map<String, Object> claimMap, final String key) {
    return Objects.requireNonNull((Map<String, Object>) claimMap.get(key), "missing claim: " + key);
  }

  private HttpResponse<String> retrieveEntityStatement() {
    return Unirest.get(testHostUrl + IdpConstants.ENTITY_STATEMENT_ENDPOINT).asString();
  }

  @Test
  void test_entityStatementResponse_ContentTypeEntityStatement() {
    assertThat(entityStatementResponseGood.getHeaders().get(HttpHeaders.CONTENT_TYPE).get(0))
        .isEqualTo("application/entity-statement+jwt;charset=UTF-8");
  }

  @Test
  void test_entityStatementResponse_JoseHeader() {
    assertThat(entityStatement.extractHeaderClaims()).containsOnlyKeys("typ", "alg", "kid");
  }

  @Test
  void test_entityStatement_BodyClaimsComplete() {
    assertThat(entityStatementbodyClaims)
        .containsOnlyKeys("iss", "sub", "iat", "exp", "jwks", "authority_hints", "metadata");
  }

  @Test
  void test_entityStatement_ContainsJwks() {
    assertThat(entityStatementbodyClaims.get("jwks")).isNotNull();
  }

  @Test
  void test_entityStatement_MetadataClaims() {
    final Map<String, Object> metadata = getInnerClaimMap(entityStatementbodyClaims, "metadata");
    assertThat(metadata).containsOnlyKeys("openid_provider", "federation_entity");
  }

  @Test
  void test_entityStatement_OpenidProviderClaimsComplete() {
    final Map<String, Object> metadata = getInnerClaimMap(entityStatementbodyClaims, "metadata");
    final Map<String, Object> openidProvider =
        Objects.requireNonNull(
            (Map<String, Object>) metadata.get("openid_provider"),
            "missing claim: openid_provider");

    assertThat(openidProvider).containsOnlyKeys(OPENID_PROVIDER_CLAIMS);
  }

  @SuppressWarnings("unchecked")
  @Test
  void test_entityStatement_OpenidProviderClaimsContentCorrect() {

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
  void test_entityStatement_FederationEntityClaimsContentCorrect() {
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

  /************************** SIGNED_JWKS_ENDPOINT *****************/

  private HttpResponse<String> retrieveSignedJwks() {
    return Unirest.get(testHostUrl + FED_SIGNED_JWKS_ENDPOINT).asString();
  }

  @Test
  void test_sigendJwksResponse_ContentTypeEntityStatement() {
    assertThat(signedJwksResponseGood.getHeaders().get(HttpHeaders.CONTENT_TYPE).get(0))
        .isEqualTo("application/jwk-set+json;charset=UTF-8");
  }

  @Test
  void test_signedJwksResponse_JoseHeader() {
    assertThat(signedJwks.extractHeaderClaims()).containsOnlyKeys("typ", "alg", "kid");
  }

  @Test
  void test_signedJwksResponse_BodyClaims() {
    assertThat(signedJwks.extractBodyClaims()).containsOnlyKeys("keys", "iss", "iat");
  }

  @Test
  void test_signedJwksResponse_Keys() {
    final List<Map<String, Object>> keyList =
        (List<Map<String, Object>>) signedJwks.getBodyClaims().get("keys");
    final List<Map<String, Object>> keyWithX5c =
        keyList.stream().filter(key -> key.containsKey("x5c")).toList();
    final List<Map<String, Object>> keyWithoutX5c =
        keyList.stream().filter(key -> !key.containsKey("x5c")).toList();
    assertThat(keyWithX5c).hasSize(1);
    assertThat(keyWithoutX5c).hasSize(1);
    assertThat(keyWithX5c.stream().findFirst().get().keySet())
        .containsExactlyInAnyOrder("use", "kid", "kty", "crv", "x", "y", "alg", "x5c");
    assertThat(keyWithoutX5c.stream().findFirst().get().keySet())
        .containsExactlyInAnyOrder("use", "kid", "kty", "crv", "x", "y", "alg");
  }

  /************************** FEDIDP_PUSHED AUTH_ENDPOINT *****************/
  @SneakyThrows
  @ValueSource(
      strings = {
        "urn:telematik:geburtsdatum urn:telematik:alter openid",
        "urn:telematik:display_name",
        "urn:telematik:given_name openid",
        "urn:telematik:geschlecht urn:telematik:versicherter urn:telematik:email"
      })
  @ParameterizedTest(name = "parRequest_validScope_ResponseStatus_CREATED scope: {0}")
  void test_postPar_validScope_201(final String scope) {
    mockMvc
        .perform(
            post(testHostUrl + FEDIDP_PAR_AUTH_ENDPOINT)
                .param("client_id", fachdienstClientId)
                .param("state", "state_Fachdienst")
                .param("redirect_uri", redirectUri)
                .param("code_challenge", ClientUtilities.generateCodeChallenge(codeVerifier))
                .param("code_challenge_method", CodeChallengeMethod.S256.toString())
                .param("response_type", "code")
                .param("nonce", "42")
                .param("scope", "urn:telematik:versicherter openid")
                .param("acr_values", "gematik-ehealth-loa-high")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE))
        .andExpect(status().isCreated())
        .andReturn();
  }

  @SneakyThrows
  @ValueSource(strings = {"gematik-ehealth-loa-high", "gematik-ehealth-loa-substantial"})
  @ParameterizedTest(name = "parRequest_validAcrValue_ResponseStatus_CREATED acr: {0}")
  void test_postPar_validAcrValue_201(final String acr_value) {

    mockMvc
        .perform(
            post(testHostUrl + FEDIDP_PAR_AUTH_ENDPOINT)
                .param("client_id", fachdienstClientId)
                .param("state", "state_Fachdienst")
                .param("redirect_uri", redirectUri)
                .param("code_challenge", ClientUtilities.generateCodeChallenge(codeVerifier))
                .param("code_challenge_method", CodeChallengeMethod.S256.toString())
                .param("response_type", "code")
                .param("nonce", "42")
                .param("scope", "urn:telematik:given_name openid")
                .param("acr_values", acr_value)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE))
        .andExpect(status().isCreated());
  }

  @SneakyThrows
  @Test
  void test_postPar_validClaims_201() {
    final JsonObject idToken = new JsonObject();

    final JsonObject amr = new JsonObject();
    final JsonArray amrValues = new JsonArray();
    amrValues.add("urn:telematik:auth:eGK");
    amr.add("values", amrValues);
    amr.addProperty("essential", true);

    final JsonObject acr = new JsonObject();
    final JsonArray acrValues = new JsonArray();
    acrValues.add(ACR_HIGH);
    acr.add("values", acrValues);
    acr.addProperty("essential", true);

    final JsonObject email = new JsonObject();
    email.addProperty("essential", true);
    final JsonObject name = new JsonObject();
    name.addProperty("essential", false);

    idToken.add("amr", amr);
    idToken.add("acr", acr);
    idToken.add("urn:telematik:claims:email", email);
    idToken.add("urn:telematik:claims:given_name", name);

    final JsonObject claims = new JsonObject();
    claims.add("id_token", idToken);

    mockMvc
        .perform(
            post(testHostUrl + FEDIDP_PAR_AUTH_ENDPOINT)
                .param("client_id", fachdienstClientId)
                .param("state", "state_Fachdienst")
                .param("redirect_uri", redirectUri)
                .param("code_challenge", ClientUtilities.generateCodeChallenge(codeVerifier))
                .param("code_challenge_method", CodeChallengeMethod.S256.toString())
                .param("response_type", "code")
                .param("nonce", "42")
                .param("scope", "urn:telematik:display_name")
                .param("acr_values", "gematik-ehealth-loa-high")
                .param("claims", claims.toString())
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE))
        .andExpect(status().isCreated())
        .andReturn();
  }

  @SneakyThrows
  @Test
  void test_postPar_claimsParamNotAJsonObject_400() {

    final MockHttpServletResponse respMsg3 =
        mockMvc
            .perform(
                post(testHostUrl + FEDIDP_PAR_AUTH_ENDPOINT)
                    .param("client_id", fachdienstClientId)
                    .param("state", "state_Fachdienst")
                    .param("redirect_uri", redirectUri)
                    .param("code_challenge", ClientUtilities.generateCodeChallenge(codeVerifier))
                    .param("code_challenge_method", CodeChallengeMethod.S256.toString())
                    .param("response_type", "code")
                    .param("nonce", "42")
                    .param("scope", "urn:telematik:display_name")
                    .param("acr_values", "gematik-ehealth-loa-high")
                    .param("claims", "invalidJsonStruct")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE))
            .andReturn()
            .getResponse();
    assertThat(respMsg3.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
    assertThat(JsonPath.read(respMsg3.getContentAsString(), "error_description").toString())
        .hasToString("parameter claims is not a JSON object");
  }

  @SneakyThrows
  @Test
  void test_postPar_claimsParamJsonButNotClaims_400() {

    final JsonObject claims = new JsonObject();
    claims.addProperty("invalid", "any");

    final MockHttpServletResponse respMsg3 =
        mockMvc
            .perform(
                post(testHostUrl + FEDIDP_PAR_AUTH_ENDPOINT)
                    .param("client_id", fachdienstClientId)
                    .param("state", "state_Fachdienst")
                    .param("redirect_uri", redirectUri)
                    .param("code_challenge", ClientUtilities.generateCodeChallenge(codeVerifier))
                    .param("code_challenge_method", CodeChallengeMethod.S256.toString())
                    .param("response_type", "code")
                    .param("nonce", "42")
                    .param("scope", "urn:telematik:display_name")
                    .param("acr_values", "gematik-ehealth-loa-high")
                    .param("claims", claims.toString())
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE))
            .andReturn()
            .getResponse();
    assertThat(respMsg3.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
    assertThat(JsonPath.read(respMsg3.getContentAsString(), "error_description").toString())
        .hasToString("parameter claims has invalid structure");
  }

  @Test
  void test_postPar_missingParameterResponseType_400() {
    final HttpResponse<String> resp =
        Unirest.post(testHostUrl + FEDIDP_PAR_AUTH_ENDPOINT)
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
  void test_postPar_invalidGetOnPostMapping_405() {
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

  /** Increase Test coverage of Landing page endpoint */
  @SneakyThrows
  @Test
  void test_postPar_invalidClientId_400() {

    mockMvc
        .perform(
            post(testHostUrl + FEDIDP_PAR_AUTH_ENDPOINT)
                .param("client_id", "invalidClientId")
                .param("state", "state_Fachdienst")
                .param("redirect_uri", redirectUri)
                .param("code_challenge", ClientUtilities.generateCodeChallenge(codeVerifier))
                .param("code_challenge_method", CodeChallengeMethod.S256.toString())
                .param("response_type", "code")
                .param("nonce", "42")
                .param("scope", "urn:telematik:given_name openid")
                .param("acr_values", "gematik-ehealth-loa-high")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE))
        .andExpect(status().isBadRequest());
  }

  /**
   * ClientID may contain just http and not https. This should work as well for local development
   * environment.
   */
  @SneakyThrows
  @Test
  void test_postPar_validClientId_201() {

    mockMvc
        .perform(
            post(testHostUrl + FEDIDP_PAR_AUTH_ENDPOINT)
                .param("client_id", "http://127.0.0.1:8084")
                .param("state", "state_Fachdienst")
                .param("redirect_uri", redirectUri)
                .param("code_challenge", ClientUtilities.generateCodeChallenge(codeVerifier))
                .param("code_challenge_method", CodeChallengeMethod.S256.toString())
                .param("response_type", "code")
                .param("nonce", "42")
                .param("scope", "urn:telematik:given_name openid")
                .param("acr_values", "gematik-ehealth-loa-high")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE))
        .andExpect(status().isCreated());
  }

  @SneakyThrows
  @Test
  void test_postPar_validAmr_201() {

    mockMvc
        .perform(
            post(testHostUrl + FEDIDP_PAR_AUTH_ENDPOINT)
                .param("client_id", fachdienstClientId)
                .param("state", "state_Fachdienst")
                .param("redirect_uri", redirectUri)
                .param("code_challenge", ClientUtilities.generateCodeChallenge(codeVerifier))
                .param("code_challenge_method", CodeChallengeMethod.S256.toString())
                .param("response_type", "code")
                .param("nonce", "42")
                .param("scope", "urn:telematik:versicherter openid")
                .param("acr_values", "gematik-ehealth-loa-high")
                .param("amr", "urn:telematik:auth:eGK")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE))
        .andExpect(status().isCreated());
  }

  @SneakyThrows
  @Test
  void test_postPar_invalidAmr_400() {

    mockMvc
        .perform(
            post(testHostUrl + FEDIDP_PAR_AUTH_ENDPOINT)
                .param("client_id", fachdienstClientId)
                .param("state", "state_Fachdienst")
                .param("redirect_uri", redirectUri)
                .param("code_challenge", ClientUtilities.generateCodeChallenge(codeVerifier))
                .param("code_challenge_method", CodeChallengeMethod.S256.toString())
                .param("response_type", "code")
                .param("nonce", "42")
                .param("scope", "urn:telematik:versicherter openid")
                .param("acr_values", "gematik-ehealth-loa-high")
                .param("amr", "urn:telematik:auth:invalid")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.error_description").value(containsString("amr: must match")));
  }

  @SneakyThrows
  @Test
  void test_postPar_validPrompt_201() {

    mockMvc
        .perform(
            post(testHostUrl + FEDIDP_PAR_AUTH_ENDPOINT)
                .param("client_id", fachdienstClientId)
                .param("state", "state_Fachdienst")
                .param("redirect_uri", redirectUri)
                .param("code_challenge", ClientUtilities.generateCodeChallenge(codeVerifier))
                .param("code_challenge_method", CodeChallengeMethod.S256.toString())
                .param("response_type", "code")
                .param("nonce", "42")
                .param("scope", "urn:telematik:versicherter openid")
                .param("acr_values", "gematik-ehealth-loa-high")
                .param("prompt", "login")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE))
        .andExpect(status().isCreated());
  }

  @SneakyThrows
  @Test
  void test_postPar_validMaxAge_201() {

    mockMvc
        .perform(
            post(testHostUrl + FEDIDP_PAR_AUTH_ENDPOINT)
                .param("client_id", fachdienstClientId)
                .param("state", "state_Fachdienst")
                .param("redirect_uri", redirectUri)
                .param("code_challenge", ClientUtilities.generateCodeChallenge(codeVerifier))
                .param("code_challenge_method", CodeChallengeMethod.S256.toString())
                .param("response_type", "code")
                .param("nonce", "42")
                .param("scope", "urn:telematik:versicherter openid")
                .param("acr_values", "gematik-ehealth-loa-high")
                .param("max_age", "0")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE))
        .andExpect(status().isCreated());
  }

  @SneakyThrows
  @Test
  void test_postPar_validTlsCertificateHeader_201() {

    mockMvc
        .perform(
            post(testHostUrl + FEDIDP_PAR_AUTH_ENDPOINT)
                .param("client_id", fachdienstClientId)
                .param("state", "state_Fachdienst")
                .param("redirect_uri", redirectUri)
                .param("code_challenge", ClientUtilities.generateCodeChallenge(codeVerifier))
                .param("code_challenge_method", CodeChallengeMethod.S256.toString())
                .param("response_type", "code")
                .param("nonce", "42")
                .param("scope", "urn:telematik:versicherter openid")
                .param("acr_values", "gematik-ehealth-loa-high")
                .header(TLS_CLIENT_CERT_HEADER_NAME, CERT1_FROM_REQUEST)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE))
        .andExpect(status().isCreated());
  }

  @SneakyThrows
  @Test
  void test_postPar_invalidTlsCertificateHeader_anyString_401() {

    requestValidatorMockedStatic
        .when(
            () ->
                RequestValidator.validateCertificate(
                    "AnyInvalidCert", VALID_RPTOKEN, gsiConfiguration.isClientCertRequired()))
        .thenThrow(
            new GsiException(
                UNAUTHORIZED_CLIENT,
                "client certificate in tls handshake is not a valid x509 certificate",
                org.springframework.http.HttpStatus.UNAUTHORIZED));

    mockMvc
        .perform(
            post(testHostUrl + FEDIDP_PAR_AUTH_ENDPOINT)
                .param("client_id", fachdienstClientId)
                .param("state", "state_Fachdienst")
                .param("redirect_uri", redirectUri)
                .param("code_challenge", ClientUtilities.generateCodeChallenge(codeVerifier))
                .param("code_challenge_method", CodeChallengeMethod.S256.toString())
                .param("response_type", "code")
                .param("nonce", "42")
                .param("scope", "urn:telematik:versicherter openid")
                .param("acr_values", "gematik-ehealth-loa-high")
                .header(TLS_CLIENT_CERT_HEADER_NAME, "AnyInvalidCert")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE))
        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.error").value(equalTo(UNAUTHORIZED_CLIENT.getSerializationValue())))
        .andExpect(
            jsonPath("$.error_description")
                .value("client certificate in tls handshake is not a valid x509 certificate"));
  }

  @SneakyThrows
  @Test
  void test_postPar_certInHeaderAndInEntityStatementDontMatch_401() {

    requestValidatorMockedStatic
        .when(
            () ->
                RequestValidator.validateCertificate(
                    CERT1_FROM_REQUEST, VALID_RPTOKEN, gsiConfiguration.isClientCertRequired()))
        .thenThrow(
            new GsiException(
                UNAUTHORIZED_CLIENT,
                "client certificate in tls handshake does not match any certificate in entity"
                    + " statement/signed_jwks",
                org.springframework.http.HttpStatus.UNAUTHORIZED));

    mockMvc
        .perform(
            post(testHostUrl + FEDIDP_PAR_AUTH_ENDPOINT)
                .param("client_id", fachdienstClientId)
                .param("state", "state_Fachdienst")
                .param("redirect_uri", redirectUri)
                .param("code_challenge", ClientUtilities.generateCodeChallenge(codeVerifier))
                .param("code_challenge_method", CodeChallengeMethod.S256.toString())
                .param("response_type", "code")
                .param("nonce", "42")
                .param("scope", "urn:telematik:versicherter openid")
                .param("acr_values", "gematik-ehealth-loa-high")
                .header(TLS_CLIENT_CERT_HEADER_NAME, CERT1_FROM_REQUEST)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE))
        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.error").value(equalTo(UNAUTHORIZED_CLIENT.getSerializationValue())))
        .andExpect(
            jsonPath("$.error_description")
                .value(
                    "client certificate in tls handshake does not match any certificate in entity"
                        + " statement/signed_jwks"));
  }

  /************************** FEDIDP AUTH_ENDPOINT *****************/
  @SneakyThrows
  @Test
  void test_getLandingPage_200() {

    final MockHttpServletResponse respMsg3 =
        mockMvc
            .perform(
                post(testHostUrl + FEDIDP_PAR_AUTH_ENDPOINT)
                    .param("client_id", testHostUrl)
                    .param("state", "state_Fachdienst")
                    .param("redirect_uri", testHostUrl + "/AS")
                    .param("code_challenge", "P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk")
                    .param("code_challenge_method", CodeChallengeMethod.S256.toString())
                    .param("response_type", "code")
                    .param("nonce", "42")
                    .param("scope", "urn:telematik:given_name openid")
                    .param("acr_values", "gematik-ehealth-loa-high")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE))
            .andReturn()
            .getResponse();

    assertThat(respMsg3.getStatus()).isEqualTo(HttpStatus.CREATED);
    final String requestUri = JsonPath.read(respMsg3.getContentAsString(), "$.request_uri");
    final HttpResponse<String> resp =
        Unirest.get(testHostUrl + FED_AUTH_ENDPOINT)
            .queryString("request_uri", requestUri)
            .queryString("client_id", testHostUrl)
            .asString();
    assertThat(resp.getStatus()).isEqualTo(HttpStatus.OK);
  }

  /*
   *  message nr.2 ... message nr.7
   * do auto registration and send invalid authorization request
   */
  @SneakyThrows
  @Test
  void test_getLandingPage_invalidClientId_invalidRequestUri_400() {

    requestValidatorMockedStatic
        .when(() -> RequestValidator.validateAuthRequestParams(any(), any()))
        .thenThrow(
            new GsiException(
                INVALID_REQUEST,
                "invalid code_verifier",
                org.springframework.http.HttpStatus.BAD_REQUEST));

    final MockHttpServletResponse respMsg3 =
        mockMvc
            .perform(
                post(testHostUrl + FEDIDP_PAR_AUTH_ENDPOINT)
                    .param("client_id", testHostUrl)
                    .param("state", "state_Fachdienst")
                    .param("redirect_uri", testHostUrl + "/AS")
                    .param("code_challenge", "P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk")
                    .param("code_challenge_method", CodeChallengeMethod.S256.toString())
                    .param("response_type", "code")
                    .param("nonce", "42")
                    .param("scope", "urn:telematik:given_name openid")
                    .param("acr_values", "gematik-ehealth-loa-high")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE))
            .andReturn()
            .getResponse();

    assertThat(respMsg3.getStatus()).isEqualTo(HttpStatus.CREATED);
    final String requestUri = JsonPath.read(respMsg3.getContentAsString(), "$.request_uri");

    // variant invalid request_uri
    mockMvc
        .perform(
            get(testHostUrl + FED_AUTH_ENDPOINT)
                .param("request_uri", "InvalidRequestUri")
                .param("client_id", testHostUrl))
        .andExpect(status().isBadRequest());

    // variant invalid client_id
    mockMvc
        .perform(
            get(testHostUrl + FED_AUTH_ENDPOINT)
                .param("request_uri", requestUri)
                .param("client_id", "InvalidClientId"))
        .andExpect(status().isBadRequest());
  }

  @SneakyThrows
  @Test
  void test_getRequestedClaims_200() {

    final MockHttpServletResponse respMsg3 =
        mockMvc
            .perform(
                post(testHostUrl + FEDIDP_PAR_AUTH_ENDPOINT)
                    .param("client_id", fachdienstClientId)
                    .param("state", "state_Fachdienst")
                    .param("redirect_uri", redirectUri)
                    .param("code_challenge", ClientUtilities.generateCodeChallenge(codeVerifier))
                    .param("code_challenge_method", CodeChallengeMethod.S256.toString())
                    .param("response_type", "code")
                    .param("nonce", "42")
                    .param("scope", "urn:telematik:given_name urn:telematik:versicherter openid")
                    .param("acr_values", "gematik-ehealth-loa-high")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE))
            .andReturn()
            .getResponse();

    assertThat(respMsg3.getStatus()).isEqualTo(HttpStatus.CREATED);
    final String requestUri = JsonPath.read(respMsg3.getContentAsString(), "$.request_uri");

    Unirest.config().reset().followRedirects(false);
    final MockHttpServletResponse respMsg6a =
        mockMvc
            .perform(
                get(testHostUrl + FED_AUTH_ENDPOINT)
                    .param("request_uri", requestUri)
                    .param("device_type", "unittest"))
            .andReturn()
            .getResponse();

    assertThat(respMsg6a.getStatus()).isEqualTo(HttpStatus.OK);

    final ClaimsResponse claimsResponse =
        new ObjectMapper().readValue(respMsg6a.getContentAsString(), ClaimsResponse.class);

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
  void test_getRequestedClaims_requestUriExpired_400() {

    final MockHttpServletResponse respMsg3 =
        mockMvc
            .perform(
                post(testHostUrl + FEDIDP_PAR_AUTH_ENDPOINT)
                    .param("client_id", fachdienstClientId)
                    .param("state", "state_Fachdienst")
                    .param("redirect_uri", redirectUri)
                    .param("code_challenge", ClientUtilities.generateCodeChallenge(codeVerifier))
                    .param("code_challenge_method", CodeChallengeMethod.S256.toString())
                    .param("response_type", "code")
                    .param("nonce", "42")
                    .param("scope", "urn:telematik:given_name urn:telematik:versicherter openid")
                    .param("acr_values", "gematik-ehealth-loa-high")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE))
            .andReturn()
            .getResponse();

    assertThat(respMsg3.getStatus()).isEqualTo(HttpStatus.CREATED);
    final String requestUri = JsonPath.read(respMsg3.getContentAsString(), "$.request_uri");

    waitForSeconds(gsiConfiguration.getRequestUriTTL() + 2);

    mockMvc
        .perform(
            get(testHostUrl + FED_AUTH_ENDPOINT)
                .param("request_uri", requestUri)
                .param("device_type", "unittest"))
        .andExpect(status().isBadRequest());
  }

  @SneakyThrows
  @Test
  void test_getAuthorizationCode_validSelectedClaims_302() {

    final MockHttpServletResponse respMsg3 =
        mockMvc
            .perform(
                post(testHostUrl + FEDIDP_PAR_AUTH_ENDPOINT)
                    .param("client_id", fachdienstClientId)
                    .param("state", "state_Fachdienst")
                    .param("redirect_uri", redirectUri)
                    .param("code_challenge", ClientUtilities.generateCodeChallenge(codeVerifier))
                    .param("code_challenge_method", CodeChallengeMethod.S256.toString())
                    .param("response_type", "code")
                    .param("nonce", "42")
                    .param("scope", "urn:telematik:versicherter openid")
                    .param("acr_values", "gematik-ehealth-loa-high")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE))
            .andReturn()
            .getResponse();
    assertThat(respMsg3.getStatus()).isEqualTo(HttpStatus.CREATED);

    final String requestUri = JsonPath.read(respMsg3.getContentAsString(), "request_uri");

    mockMvc
        .perform(
            get(testHostUrl + FED_AUTH_ENDPOINT)
                .param("request_uri", requestUri)
                .param("device_type", "unittest"))
        .andExpect(status().isOk());

    mockMvc
        .perform(
            get(testHostUrl + FED_AUTH_ENDPOINT)
                .param("request_uri", requestUri)
                .param("user_id", "12345678")
                .param("selected_claims", "urn:telematik:claims:id"))
        .andExpect(status().isFound());
  }

  @SneakyThrows
  @Test
  void test_getAuthorizationCode_invalidSelectedClaims_400() {

    final MockHttpServletResponse respMsg3 =
        mockMvc
            .perform(
                post(testHostUrl + FEDIDP_PAR_AUTH_ENDPOINT)
                    .param("client_id", fachdienstClientId)
                    .param("state", "state_Fachdienst")
                    .param("redirect_uri", redirectUri)
                    .param("code_challenge", ClientUtilities.generateCodeChallenge(codeVerifier))
                    .param("code_challenge_method", CodeChallengeMethod.S256.toString())
                    .param("response_type", "code")
                    .param("nonce", "42")
                    .param("scope", "urn:telematik:versicherter openid")
                    .param("acr_values", "gematik-ehealth-loa-high")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE))
            .andReturn()
            .getResponse();
    assertThat(respMsg3.getStatus()).isEqualTo(HttpStatus.CREATED);

    final String requestUri = JsonPath.read(respMsg3.getContentAsString(), "request_uri");

    mockMvc
        .perform(
            get(testHostUrl + FED_AUTH_ENDPOINT)
                .param("request_uri", requestUri)
                .param("device_type", "unittest"))
        .andExpect(status().isOk());

    mockMvc
        .perform(
            get(testHostUrl + FED_AUTH_ENDPOINT)
                .param("request_uri", requestUri)
                .param("user_id", "12345678")
                .param("selected_claims", "urn:telematik:claims:given_name"))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.error_description").value("selected claims exceed scopes in PAR"));
  }

  /************************** FEDIDP_TOKEN_ENDPOINT *****************/
  @Test
  void test_getTokensForCode_invalidCode_400() {
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
  void test_getTokensForCode_invalidGrantType_400() {
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
  void test_getTokensForCode_invalidGetOnPostMapping_405() {
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
  void test_getTokensForCode_200() {

    final MockHttpServletResponse respMsg3 =
        mockMvc
            .perform(
                post(testHostUrl + FEDIDP_PAR_AUTH_ENDPOINT)
                    .param("client_id", fachdienstClientId)
                    .param("state", "state_Fachdienst")
                    .param("redirect_uri", redirectUri)
                    .param("code_challenge", ClientUtilities.generateCodeChallenge(codeVerifier))
                    .param("code_challenge_method", CodeChallengeMethod.S256.toString())
                    .param("response_type", "code")
                    .param("nonce", "42")
                    .param(
                        "scope",
                        "urn:telematik:given_name urn:telematik:display_name"
                            + " urn:telematik:versicherter openid")
                    .param("acr_values", "gematik-ehealth-loa-high")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE))
            .andReturn()
            .getResponse();

    assertThat(respMsg3.getStatus()).isEqualTo(HttpStatus.CREATED);

    final String requestUri = JsonPath.read(respMsg3.getContentAsString(), "$.request_uri");

    final MockHttpServletResponse respMsg7 =
        mockMvc
            .perform(
                get(testHostUrl + FED_AUTH_ENDPOINT)
                    .param("request_uri", requestUri)
                    .param("user_id", "12345678"))
            .andReturn()
            .getResponse();

    assertThat(respMsg7.getStatus()).isEqualTo(HttpStatus.FOUND);

    final String code =
        UriUtils.extractParameterValue(respMsg7.getHeaders("Location").get(0), "code");

    final MockHttpServletResponse resp =
        mockMvc
            .perform(
                post(testHostUrl + TOKEN_ENDPOINT)
                    .param("grant_type", "authorization_code")
                    .param("code", code)
                    .param("code_verifier", codeVerifier)
                    .param("client_id", fachdienstClientId)
                    .param("redirect_uri", redirectUri)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                    .header(HttpHeaders.USER_AGENT, "IdP-Client")
                    .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE))
            .andReturn()
            .getResponse();

    assertThat(resp.getStatus()).isEqualTo(HttpStatus.OK);

    final String idTokenEncrypted = JsonPath.read(resp.getContentAsString(), "$.id_token");
    final IdpJwe idpJwe = new IdpJwe(idTokenEncrypted);

    // verify that token is encrypted and check kid
    assertThat(idpJwe.extractHeaderClaims()).containsEntry("kid", KEY_ID);
  }

  @SneakyThrows
  @Test
  void test_getTokensForCode_withSelectedClaims_200() {

    final MockHttpServletResponse respMsg3 =
        mockMvc
            .perform(
                post(testHostUrl + FEDIDP_PAR_AUTH_ENDPOINT)
                    .param("client_id", fachdienstClientId)
                    .param("state", "state_Fachdienst")
                    .param("redirect_uri", redirectUri)
                    .param("code_challenge", ClientUtilities.generateCodeChallenge(codeVerifier))
                    .param("code_challenge_method", CodeChallengeMethod.S256.toString())
                    .param("response_type", "code")
                    .param("nonce", "42")
                    .param("scope", "urn:telematik:versicherter openid")
                    .param("acr_values", "gematik-ehealth-loa-high")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE))
            .andReturn()
            .getResponse();

    assertThat(respMsg3.getStatus()).isEqualTo(HttpStatus.CREATED);

    final String requestUri = JsonPath.read(respMsg3.getContentAsString(), "$.request_uri");

    final MockHttpServletResponse respMsg6a =
        mockMvc
            .perform(
                get(testHostUrl + FED_AUTH_ENDPOINT)
                    .param("request_uri", requestUri)
                    .param("device_type", "unittest"))
            .andReturn()
            .getResponse();

    assertThat(respMsg6a.getStatus()).isEqualTo(HttpStatus.OK);

    final MockHttpServletResponse respMsg7 =
        mockMvc
            .perform(
                get(testHostUrl + FED_AUTH_ENDPOINT)
                    .param("request_uri", requestUri)
                    .param("user_id", "12345678")
                    .param(
                        "selected_claims",
                        "urn:telematik:claims:profession urn:telematik:claims:id"))
            .andReturn()
            .getResponse();

    assertThat(respMsg7.getStatus()).isEqualTo(HttpStatus.FOUND);

    final String code =
        UriUtils.extractParameterValue(respMsg7.getHeaders("Location").get(0), "code");

    final MockHttpServletResponse resp =
        mockMvc
            .perform(
                post(testHostUrl + TOKEN_ENDPOINT)
                    .param("grant_type", "authorization_code")
                    .param("code", code)
                    .param("code_verifier", codeVerifier)
                    .param("client_id", fachdienstClientId)
                    .param("redirect_uri", redirectUri)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                    .header(HttpHeaders.USER_AGENT, "IdP-Client")
                    .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE))
            .andReturn()
            .getResponse();

    assertThat(resp.getStatus()).isEqualTo(HttpStatus.OK);

    final String idTokenEncrypted = JsonPath.read(resp.getContentAsString(), "$.id_token");
    final IdpJwe idpJwe = new IdpJwe(idTokenEncrypted);

    // verify that token is encrypted and check kid
    assertThat(idpJwe.extractHeaderClaims()).containsEntry("kid", KEY_ID);
  }

  /** Increase Test coverage of Token endpoint */
  @SneakyThrows
  @Test
  void test_getTokensForCode_invalidRedirectUri_invalidCodeVerifier_400() {

    requestValidatorMockedStatic
        .when(() -> RequestValidator.verifyRedirectUri("invalidRedirectUri", redirectUri))
        .thenThrow(
            new GsiException(
                INVALID_REQUEST,
                "invalid redirect_uri",
                org.springframework.http.HttpStatus.BAD_REQUEST));

    requestValidatorMockedStatic
        .when(
            () ->
                RequestValidator.verifyCodeVerifier(
                    "invalidCodeVerifier", ClientUtilities.generateCodeChallenge(codeVerifier)))
        .thenThrow(
            new GsiException(
                INVALID_REQUEST,
                "invalid redirect_uri",
                org.springframework.http.HttpStatus.BAD_REQUEST));

    final MockHttpServletResponse respMsg3 =
        mockMvc
            .perform(
                post(testHostUrl + FEDIDP_PAR_AUTH_ENDPOINT)
                    .param("client_id", fachdienstClientId)
                    .param("state", "state_Fachdienst")
                    .param("redirect_uri", redirectUri)
                    .param("code_challenge", ClientUtilities.generateCodeChallenge(codeVerifier))
                    .param("code_challenge_method", CodeChallengeMethod.S256.toString())
                    .param("response_type", "code")
                    .param("nonce", "42")
                    .param("scope", "urn:telematik:given_name openid")
                    .param("acr_values", "gematik-ehealth-loa-high")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE))
            .andReturn()
            .getResponse();

    assertThat(respMsg3.getStatus()).isEqualTo(HttpStatus.CREATED);

    final String requestUri = JsonPath.read(respMsg3.getContentAsString(), "request_uri");

    final MockHttpServletResponse respMsg7 =
        mockMvc
            .perform(
                get(testHostUrl + FED_AUTH_ENDPOINT)
                    .param("request_uri", requestUri)
                    .param("user_id", "12345678"))
            .andReturn()
            .getResponse();

    assertThat(respMsg7.getStatus()).isEqualTo(HttpStatus.FOUND);

    final String code =
        UriUtils.extractParameterValue(respMsg7.getHeaders("Location").get(0), "code");

    // invalid code verifier
    mockMvc
        .perform(
            post(testHostUrl + TOKEN_ENDPOINT)
                .param("grant_type", "authorization_code")
                .param("code", code)
                .param("code_verifier", "invalidCodeVerifier")
                .param("client_id", fachdienstClientId)
                .param("redirect_uri", redirectUri)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .header(HttpHeaders.USER_AGENT, "IdP-Client")
                .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE))
        .andExpect(status().isBadRequest());

    // invalid redirect uri
    mockMvc
        .perform(
            post(testHostUrl + TOKEN_ENDPOINT)
                .param("grant_type", "authorization_code")
                .param("code", code)
                .param("code_verifier", codeVerifier)
                .param("client_id", fachdienstClientId)
                .param("redirect_uri", "invalidRedirectUri")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .header(HttpHeaders.USER_AGENT, "IdP-Client"))
        .andExpect(status().isBadRequest());
  }

  @SneakyThrows
  @Test
  void test_getTokensForCode_tlsCertificateHeader_200() {

    final MockHttpServletResponse respMsg3 =
        mockMvc
            .perform(
                post(testHostUrl + FEDIDP_PAR_AUTH_ENDPOINT)
                    .param("client_id", fachdienstClientId)
                    .param("state", "state_Fachdienst")
                    .param("redirect_uri", redirectUri)
                    .param("code_challenge", ClientUtilities.generateCodeChallenge(codeVerifier))
                    .param("code_challenge_method", CodeChallengeMethod.S256.toString())
                    .param("response_type", "code")
                    .param("nonce", "42")
                    .param("scope", "urn:telematik:versicherter openid")
                    .param("acr_values", "gematik-ehealth-loa-high")
                    .header(TLS_CLIENT_CERT_HEADER_NAME, CERT1_FROM_REQUEST)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE))
            .andReturn()
            .getResponse();

    assertThat(respMsg3.getStatus()).isEqualTo(HttpStatus.CREATED);

    final String requestUri = JsonPath.read(respMsg3.getContentAsString(), "$.request_uri");

    final MockHttpServletResponse respMsg7 =
        mockMvc
            .perform(
                get(testHostUrl + FED_AUTH_ENDPOINT)
                    .param("request_uri", requestUri)
                    .param("user_id", "12345678"))
            .andReturn()
            .getResponse();

    assertThat(respMsg7.getStatus()).isEqualTo(HttpStatus.FOUND);

    final String code =
        UriUtils.extractParameterValue(respMsg7.getHeaders("Location").get(0), "code");

    mockMvc
        .perform(
            post(testHostUrl + TOKEN_ENDPOINT)
                .param("grant_type", "authorization_code")
                .param("code", code)
                .param("code_verifier", codeVerifier)
                .param("client_id", fachdienstClientId)
                .param("redirect_uri", redirectUri)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .header(HttpHeaders.USER_AGENT, "IdP-Client")
                .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
                .header(TLS_CLIENT_CERT_HEADER_NAME, CERT1_FROM_REQUEST))
        .andExpect(status().isOk());
  }

  private void waitForSeconds(final int seconds) {
    Awaitility.await()
        .atMost(seconds + 1, TimeUnit.SECONDS)
        .pollDelay(seconds, TimeUnit.SECONDS)
        .until(() -> true);
  }
}
