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

package de.gematik.idp.gsi.server.controller;

import static de.gematik.idp.data.Oauth2ErrorCode.UNAUTHORIZED_CLIENT;
import static de.gematik.idp.gsi.server.common.Constants.ENTITY_STMNT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2043;
import static de.gematik.idp.gsi.server.data.GsiConstants.*;
import static de.gematik.idp.gsi.server.services.ValidClaimsParamObject.getValidClaimsParameterObject;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.ArgumentMatchers.any;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.google.gson.JsonObject;
import com.jayway.jsonpath.JsonPath;
import de.gematik.idp.field.ClientUtilities;
import de.gematik.idp.field.CodeChallengeMethod;
import de.gematik.idp.gsi.server.GsiServer;
import de.gematik.idp.gsi.server.configuration.GsiConfiguration;
import de.gematik.idp.gsi.server.data.RpToken;
import de.gematik.idp.gsi.server.exceptions.GsiException;
import de.gematik.idp.gsi.server.services.EntityStatementRpReader;
import de.gematik.idp.gsi.server.services.RequestValidator;
import de.gematik.idp.gsi.server.services.TokenRepositoryRp;
import de.gematik.idp.token.JsonWebToken;
import kong.unirest.core.HttpResponse;
import kong.unirest.core.HttpStatus;
import kong.unirest.core.Unirest;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.jose4j.jwk.PublicJsonWebKey;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

@Slf4j
@SpringBootTest(
    classes = GsiServer.class,
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class FedIdpControllerPostParTest {
  private MockMvc mockMvc;
  @Autowired private WebApplicationContext context;
  @Autowired private GsiConfiguration gsiConfiguration;
  @MockitoBean private TokenRepositoryRp rpTokenRepository;
  private static MockedStatic<RequestValidator> requestValidatorMockedStatic;
  private static MockedStatic<EntityStatementRpReader> esReaderMockedStatic;
  private String testHostUrl;
  @LocalServerPort private int serverPort;
  private String codeVerifier;
  private String redirectUri;
  private String fachdienstClientId;
  private static final RpToken VALID_RPTOKEN =
      new RpToken(new JsonWebToken(ENTITY_STMNT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2043));
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
    final JsonObject claimsParameter = getValidClaimsParameterObject();

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
                .param("claims", claimsParameter.toString())
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
}
