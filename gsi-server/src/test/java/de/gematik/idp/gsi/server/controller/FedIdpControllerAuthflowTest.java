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

import static de.gematik.idp.IdpConstants.FED_AUTH_ENDPOINT;
import static de.gematik.idp.data.Oauth2ErrorCode.INVALID_REQUEST;
import static de.gematik.idp.gsi.server.common.Constants.ENTITY_STMNT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2043;
import static de.gematik.idp.gsi.server.data.GsiConstants.*;
import static de.gematik.idp.gsi.server.services.ValidClaimsParamObject.getValidClaimsParameterObject;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.google.gson.JsonObject;
import com.jayway.jsonpath.JsonPath;
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
import de.gematik.idp.token.JsonWebToken;
import java.util.concurrent.TimeUnit;
import kong.unirest.core.HttpResponse;
import kong.unirest.core.HttpStatus;
import kong.unirest.core.Unirest;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.awaitility.Awaitility;
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
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import tools.jackson.databind.json.JsonMapper;

@Slf4j
@SpringBootTest(
    classes = GsiServer.class,
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class FedIdpControllerAuthflowTest {
  private MockMvc mockMvc;

  @DynamicPropertySource
  static void dynamicProperties(final DynamicPropertyRegistry registry) {
    registry.add("gsi.requestUriTTL", () -> 5);
  }

  @Autowired private WebApplicationContext context;
  @Autowired private GsiConfiguration gsiConfiguration;
  @MockitoBean private TokenRepositoryRp rpTokenRepository;
  @LocalServerPort private int serverPort;

  private static MockedStatic<RequestValidator> requestValidatorMockedStatic;
  private static MockedStatic<EntityStatementRpReader> esReaderMockedStatic;

  private String testHostUrl;
  private String codeVerifier;
  private String redirectUri;
  private String fachdienstClientId;
  private String stateFachdienst;
  private String codeChallenge;
  private String responseType;
  private String nonce;
  private String acrValues;

  private static final RpToken VALID_RPTOKEN =
      new RpToken(new JsonWebToken(ENTITY_STMNT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2043));
  private static final String KEY_ID = "puk_fd_enc";

  private void waitForSeconds(final int seconds) {
    Awaitility.await()
        .atMost(seconds + 1, TimeUnit.SECONDS)
        .pollDelay(seconds, TimeUnit.SECONDS)
        .until(() -> true);
  }

  @SneakyThrows
  @BeforeAll
  void setup() {
    testHostUrl = "http://localhost:" + serverPort;
    codeVerifier = ClientUtilities.generateCodeVerifier();
    redirectUri = testHostUrl + "/AS";
    fachdienstClientId = testHostUrl;
    stateFachdienst = "state_Fachdienst";
    codeChallenge = "P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk";
    responseType = "code";
    nonce = "42";
    acrValues = "gematik-ehealth-loa-high";
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
  @ValueSource(strings = {"1.0.0", "2.0.0"})
  @ParameterizedTest(name = "test_getLandingPage_200 idTokenVersion: {0}")
  void test_getLandingPage_200(final String idTokenVersion) {
    final JsonObject claimsParameter = getValidClaimsParameterObject();

    requestValidatorMockedStatic
        .when(() -> RequestValidator.validateAndSelectCompatibleIdTokenVersion(any()))
        .thenReturn(idTokenVersion);

    final MockHttpServletResponse respMsg3 =
        mockMvc
            .perform(
                post(testHostUrl + FEDIDP_PAR_AUTH_ENDPOINT)
                    .param("client_id", testHostUrl)
                    .param("state", stateFachdienst)
                    .param("redirect_uri", redirectUri)
                    .param("code_challenge", codeChallenge)
                    .param("code_challenge_method", CodeChallengeMethod.S256.toString())
                    .param("response_type", responseType)
                    .param("nonce", nonce)
                    .param("scope", "urn:telematik:given_name openid")
                    .param("acr_values", acrValues)
                    .param("claims", claimsParameter.toString())
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
   *  message nr.2 ... message nr.6
   * do auto registration and send invalid authorization request
   */
  @SneakyThrows
  @Test
  void test_getLandingPage_invalidClientId_mockedValidation_testErrorResponse_400() {

    final MockHttpServletResponse respMsg3 =
        mockMvc
            .perform(
                post(testHostUrl + FEDIDP_PAR_AUTH_ENDPOINT)
                    .param("client_id", testHostUrl)
                    .param("state", stateFachdienst)
                    .param("redirect_uri", redirectUri)
                    .param("code_challenge", codeChallenge)
                    .param("code_challenge_method", CodeChallengeMethod.S256.toString())
                    .param("response_type", responseType)
                    .param("nonce", nonce)
                    .param("scope", "urn:telematik:given_name openid")
                    .param("acr_values", acrValues)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE))
            .andReturn()
            .getResponse();

    assertThat(respMsg3.getStatus()).isEqualTo(HttpStatus.CREATED);
    final String requestUri = JsonPath.read(respMsg3.getContentAsString(), "$.request_uri");

    requestValidatorMockedStatic
        .when(() -> RequestValidator.validateAuthRequestParams(any(), any()))
        .thenThrow(
            new GsiException(
                INVALID_REQUEST,
                "unknown client_id",
                org.springframework.http.HttpStatus.BAD_REQUEST));

    mockMvc
        .perform(
            get(testHostUrl + FED_AUTH_ENDPOINT)
                .param("request_uri", requestUri)
                .param("client_id", "InvalidClientId"))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.error_description").value("unknown client_id"));
  }

  /*
   * message nr.6
   * send invalid authorization request
   */
  @SneakyThrows
  @Test
  void test_getLandingPage_invalidRequestUri_400() {

    mockMvc
        .perform(
            get(testHostUrl + FED_AUTH_ENDPOINT)
                .param("request_uri", "InvalidRequestUri")
                .param("client_id", testHostUrl))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.error_description").value("unknown request_uri, no session found"));
  }

  /*
   *  message nr.2 ... message nr.6
   * do auto registration and send invalid authorization request
   */
  @SneakyThrows
  @Test
  void test_getLandingPage_expiredRequestUri_400() {
    final MockHttpServletResponse respMsg3 =
        mockMvc
            .perform(
                post(testHostUrl + FEDIDP_PAR_AUTH_ENDPOINT)
                    .param("client_id", testHostUrl)
                    .param("state", stateFachdienst)
                    .param("redirect_uri", redirectUri)
                    .param("code_challenge", codeChallenge)
                    .param("code_challenge_method", CodeChallengeMethod.S256.toString())
                    .param("response_type", responseType)
                    .param("nonce", nonce)
                    .param("scope", "urn:telematik:given_name openid")
                    .param("acr_values", acrValues)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE))
            .andReturn()
            .getResponse();

    assertThat(respMsg3.getStatus()).isEqualTo(HttpStatus.CREATED);
    final String requestUri = JsonPath.read(respMsg3.getContentAsString(), "$.request_uri");

    waitForSeconds(6);

    mockMvc
        .perform(
            get(testHostUrl + FED_AUTH_ENDPOINT)
                .param("request_uri", requestUri)
                .param("client_id", testHostUrl))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.error_description").value("request_uri expired"));
  }

  @SneakyThrows
  @Test
  void test_getRequestedClaims_200() {

    final MockHttpServletResponse respMsg3 =
        mockMvc
            .perform(
                post(testHostUrl + FEDIDP_PAR_AUTH_ENDPOINT)
                    .param("client_id", fachdienstClientId)
                    .param("state", stateFachdienst)
                    .param("redirect_uri", redirectUri)
                    .param("code_challenge", ClientUtilities.generateCodeChallenge(codeVerifier))
                    .param("code_challenge_method", CodeChallengeMethod.S256.toString())
                    .param("response_type", responseType)
                    .param("nonce", nonce)
                    .param("scope", "urn:telematik:given_name urn:telematik:versicherter openid")
                    .param("acr_values", acrValues)
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
        JsonMapper.builder()
            .build()
            .readValue(respMsg6a.getContentAsString(), ClaimsResponse.class);

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
  void test_getRequestedEssentialAndOptionalClaims_noClaimsParameter_200() {

    final MockHttpServletResponse respMsg3 =
        mockMvc
            .perform(
                post(testHostUrl + FEDIDP_PAR_AUTH_ENDPOINT)
                    .param("client_id", fachdienstClientId)
                    .param("state", stateFachdienst)
                    .param("redirect_uri", redirectUri)
                    .param("code_challenge", ClientUtilities.generateCodeChallenge(codeVerifier))
                    .param("code_challenge_method", CodeChallengeMethod.S256.toString())
                    .param("response_type", responseType)
                    .param("nonce", nonce)
                    .param("scope", "urn:telematik:given_name urn:telematik:versicherter openid")
                    .param("acr_values", acrValues)
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
                    .param("app_version", "unittest001"))
            .andReturn()
            .getResponse();

    assertThat(respMsg6a.getStatus()).isEqualTo(HttpStatus.OK);

    final ClaimsResponse claimsResponse =
        JsonMapper.builder()
            .build()
            .readValue(respMsg6a.getContentAsString(), ClaimsResponse.class);

    assertThat(claimsResponse).isNotNull();
    assertThat(claimsResponse.getRequestedClaims()).isNull();
    assertThat(claimsResponse.getRequestedEssentialClaims()).isEmpty();
    assertThat(claimsResponse.getRequestedOptionalClaims())
        .containsExactlyInAnyOrder(
            "urn:telematik:claims:profession",
            "urn:telematik:claims:id",
            "urn:telematik:claims:organization",
            "urn:telematik:claims:given_name");
  }

  @SneakyThrows
  @Test
  void test_getRequestedEssentialAndOptionalClaims_withClaimsParameter_200() {

    final JsonObject claimsParameter = getValidClaimsParameterObject();

    final MockHttpServletResponse respMsg3 =
        mockMvc
            .perform(
                post(testHostUrl + FEDIDP_PAR_AUTH_ENDPOINT)
                    .param("client_id", fachdienstClientId)
                    .param("state", stateFachdienst)
                    .param("redirect_uri", redirectUri)
                    .param("code_challenge", ClientUtilities.generateCodeChallenge(codeVerifier))
                    .param("code_challenge_method", CodeChallengeMethod.S256.toString())
                    .param("response_type", responseType)
                    .param("nonce", nonce)
                    .param("scope", "urn:telematik:given_name urn:telematik:versicherter openid")
                    .param("acr_values", acrValues)
                    .param("claims", claimsParameter.toString())
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
                    .param("app_version", "unittest001"))
            .andReturn()
            .getResponse();

    assertThat(respMsg6a.getStatus()).isEqualTo(HttpStatus.OK);

    final ClaimsResponse claimsResponse =
        JsonMapper.builder()
            .build()
            .readValue(respMsg6a.getContentAsString(), ClaimsResponse.class);

    assertThat(claimsResponse).isNotNull();
    assertThat(claimsResponse.getRequestedClaims()).isNull();
    assertThat(claimsResponse.getRequestedEssentialClaims())
        .containsExactlyInAnyOrder("urn:telematik:claims:given_name");
    assertThat(claimsResponse.getRequestedOptionalClaims())
        .containsExactlyInAnyOrder(
            "urn:telematik:claims:profession",
            "urn:telematik:claims:id",
            "urn:telematik:claims:organization",
            "urn:telematik:claims:email");
  }

  @SneakyThrows
  @Test
  void test_getRequestedClaims_requestUriExpired_400() {

    final MockHttpServletResponse respMsg3 =
        mockMvc
            .perform(
                post(testHostUrl + FEDIDP_PAR_AUTH_ENDPOINT)
                    .param("client_id", fachdienstClientId)
                    .param("state", stateFachdienst)
                    .param("redirect_uri", redirectUri)
                    .param("code_challenge", ClientUtilities.generateCodeChallenge(codeVerifier))
                    .param("code_challenge_method", CodeChallengeMethod.S256.toString())
                    .param("response_type", responseType)
                    .param("nonce", nonce)
                    .param("scope", "urn:telematik:given_name urn:telematik:versicherter openid")
                    .param("acr_values", acrValues)
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
  @ValueSource(strings = {"1.0.0", "2.0.0"})
  @ParameterizedTest(name = "test_getAuthorizationCode_validSelectedClaims_302 idTokenVersion: {0}")
  void test_getAuthorizationCode_validSelectedClaims_302(final String idTokenVersion) {

    requestValidatorMockedStatic
        .when(() -> RequestValidator.validateAndSelectCompatibleIdTokenVersion(any()))
        .thenReturn(idTokenVersion);

    final MockHttpServletResponse respMsg3 =
        mockMvc
            .perform(
                post(testHostUrl + FEDIDP_PAR_AUTH_ENDPOINT)
                    .param("client_id", fachdienstClientId)
                    .param("state", stateFachdienst)
                    .param("redirect_uri", redirectUri)
                    .param("code_challenge", ClientUtilities.generateCodeChallenge(codeVerifier))
                    .param("code_challenge_method", CodeChallengeMethod.S256.toString())
                    .param("response_type", responseType)
                    .param("nonce", nonce)
                    .param("scope", "urn:telematik:versicherter openid")
                    .param("acr_values", acrValues)
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
                .param("user_id", FALLBACK_KVNR)
                .param("selected_claims", "urn:telematik:claims:id"))
        .andExpect(status().isFound());
  }

  @SneakyThrows
  @Test
  void test_getAuthorizationCode_invalidUserId() {

    final MockHttpServletResponse respMsg3 =
        mockMvc
            .perform(
                post(testHostUrl + FEDIDP_PAR_AUTH_ENDPOINT)
                    .param("client_id", fachdienstClientId)
                    .param("state", stateFachdienst)
                    .param("redirect_uri", redirectUri)
                    .param("code_challenge", ClientUtilities.generateCodeChallenge(codeVerifier))
                    .param("code_challenge_method", CodeChallengeMethod.S256.toString())
                    .param("response_type", responseType)
                    .param("nonce", nonce)
                    .param("scope", "urn:telematik:versicherter openid")
                    .param("acr_values", acrValues)
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

    final MockHttpServletResponse resp =
        mockMvc
            .perform(
                get(testHostUrl + FED_AUTH_ENDPOINT)
                    .param("request_uri", requestUri)
                    .param("user_id", "12345678")
                    .param("selected_claims", "urn:telematik:claims:id"))
            .andReturn()
            .getResponse();
    assertThat(resp.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
    assertThat(JsonPath.read(resp.getContentAsString(), "error_description").toString())
        .contains("userId: must match \"^[A-Z]\\d{9}$\"");
  }

  @SneakyThrows
  @Test
  void test_getAuthorizationCode_unknownUserId() {

    final MockHttpServletResponse respMsg3 =
        mockMvc
            .perform(
                post(testHostUrl + FEDIDP_PAR_AUTH_ENDPOINT)
                    .param("client_id", fachdienstClientId)
                    .param("state", stateFachdienst)
                    .param("redirect_uri", redirectUri)
                    .param("code_challenge", ClientUtilities.generateCodeChallenge(codeVerifier))
                    .param("code_challenge_method", CodeChallengeMethod.S256.toString())
                    .param("response_type", responseType)
                    .param("nonce", nonce)
                    .param("scope", "urn:telematik:versicherter openid")
                    .param("acr_values", acrValues)
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

    final MockHttpServletResponse resp =
        mockMvc
            .perform(
                get(testHostUrl + FED_AUTH_ENDPOINT)
                    .param("request_uri", requestUri)
                    .param("user_id", "W123456789")
                    .param("selected_claims", "urn:telematik:claims:id"))
            .andReturn()
            .getResponse();
    assertThat(resp.getStatus()).isEqualTo(HttpStatus.FOUND);
    assertThat(resp.getHeader("Location")).contains("code");
  }

  @SneakyThrows
  @Test
  void test_getAuthorizationCode_invalidSelectedClaims_400() {

    final MockHttpServletResponse respMsg3 =
        mockMvc
            .perform(
                post(testHostUrl + FEDIDP_PAR_AUTH_ENDPOINT)
                    .param("client_id", fachdienstClientId)
                    .param("state", stateFachdienst)
                    .param("redirect_uri", redirectUri)
                    .param("code_challenge", ClientUtilities.generateCodeChallenge(codeVerifier))
                    .param("code_challenge_method", CodeChallengeMethod.S256.toString())
                    .param("response_type", responseType)
                    .param("nonce", nonce)
                    .param("scope", "urn:telematik:versicherter openid")
                    .param("acr_values", acrValues)
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
                .param("user_id", FALLBACK_KVNR)
                .param("selected_claims", "urn:telematik:claims:given_name"))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.error_description").value("selected claims exceed scopes in PAR"));
  }

  @SneakyThrows
  @Test
  void test_getAuthorizationCode_missingEssentialClaims_400() {

    final JsonObject claimsParameter = getValidClaimsParameterObject();

    final MockHttpServletResponse respMsg3 =
        mockMvc
            .perform(
                post(testHostUrl + FEDIDP_PAR_AUTH_ENDPOINT)
                    .param("client_id", fachdienstClientId)
                    .param("state", stateFachdienst)
                    .param("redirect_uri", redirectUri)
                    .param("code_challenge", ClientUtilities.generateCodeChallenge(codeVerifier))
                    .param("code_challenge_method", CodeChallengeMethod.S256.toString())
                    .param("response_type", responseType)
                    .param("nonce", nonce)
                    .param("scope", "urn:telematik:given_name urn:telematik:versicherter openid")
                    .param("acr_values", acrValues)
                    .param("claims", claimsParameter.toString())
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE))
            .andReturn()
            .getResponse();

    final String requestUri = JsonPath.read(respMsg3.getContentAsString(), "request_uri");

    mockMvc
        .perform(
            get(testHostUrl + FED_AUTH_ENDPOINT)
                .param("request_uri", requestUri)
                .param("device_type", "unittest"))
        .andExpect(status().isOk());

    final String selectedClaimsMissingEssentialGivenName = "urn:telematik:claims:id";
    mockMvc
        .perform(
            get(testHostUrl + FED_AUTH_ENDPOINT)
                .param("request_uri", requestUri)
                .param("user_id", FALLBACK_KVNR)
                .param("selected_claims", selectedClaimsMissingEssentialGivenName))
        .andExpect(status().isBadRequest())
        .andExpect(
            jsonPath("$.error_description")
                .value("selected claims are missing essential claims in PAR"));
  }
}
