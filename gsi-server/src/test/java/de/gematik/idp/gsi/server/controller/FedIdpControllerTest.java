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
import static de.gematik.idp.gsi.server.data.GsiConstants.FEDIDP_PAR_AUTH_ENDPOINT;
import static de.gematik.idp.gsi.server.data.GsiConstants.FED_SIGNED_JWKS_ENDPOINT;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import de.gematik.idp.IdpConstants;
import de.gematik.idp.authentication.UriUtils;
import de.gematik.idp.field.ClientUtilities;
import de.gematik.idp.field.CodeChallengeMethod;
import de.gematik.idp.gsi.server.GsiServer;
import de.gematik.idp.gsi.server.services.EntityStatementRpService;
import de.gematik.idp.token.IdpJwe;
import de.gematik.idp.token.JsonWebToken;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import kong.unirest.HttpResponse;
import kong.unirest.HttpStatus;
import kong.unirest.JsonNode;
import kong.unirest.Unirest;
import lombok.SneakyThrows;
import org.apache.http.HttpHeaders;
import org.jose4j.jwk.PublicJsonWebKey;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;

@ActiveProfiles("test-controller")
@SpringBootTest(
    classes = GsiServer.class,
    webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class FedIdpControllerTest {

  @Autowired
  private EntityStatementRpService entityStatementRpService;
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
          "user_type_supported");

  @Value("${server.port}")
  private int serverPort;

  private String testHostUrl;
  private HttpResponse<String> entityStatementResponseGood;
  private JsonWebToken entityStatement;

  private HttpResponse<String> sigendJwksResponseGood;
  private JsonWebToken sigendJwks;
  private Map<String, Object> entityStatementbodyClaims;

  @BeforeAll
  void setup() {
    testHostUrl = "http://localhost:" + serverPort;
    entityStatementResponseGood = retrieveEntityStatement();
    sigendJwksResponseGood = retrieveSignedJwks();
    assertThat(entityStatementResponseGood.getStatus()).isEqualTo(HttpStatus.OK);
    entityStatement = new JsonWebToken(entityStatementResponseGood.getBody());
    sigendJwks = new JsonWebToken(sigendJwksResponseGood.getBody());
    entityStatementbodyClaims = entityStatement.extractBodyClaims();
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
        .containsEntry("token_endpoint", gsiServerUrl + "/token")
        .containsEntry("pushed_authorization_request_endpoint", gsiServerUrl + "/PAR_Auth");
    assertThat((List) openidProvider.get("client_registration_types_supported"))
        .containsExactlyInAnyOrder("automatic");
    assertThat((List) openidProvider.get("subject_types_supported"))
        .hasSize(1)
        .isSubsetOf(List.of("pairwise", "public"));
    assertThat((List) openidProvider.get("response_types_supported"))
        .containsExactlyInAnyOrder("code");
    assertThat((List) openidProvider.get("scopes_supported"))
        .containsExactlyInAnyOrder(
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

    assertThat(federationEntity)
        .containsEntry("name", "gematik sektoraler IDP")
        .containsEntry("contacts", "support@idp4711.de")
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
    assertThat(sigendJwks.extractBodyClaims()).containsOnlyKeys("keys");
  }

  @Test
  void signedJwksResponse_Keys() {
    final List<Map<String, Object>> keyList =
        (List<Map<String, Object>>) sigendJwks.getBodyClaims().get("keys");
    assertThat(keyList.get(0).keySet())
        .containsExactlyInAnyOrder("use", "kid", "kty", "crv", "x", "y");
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
  @ParameterizedTest
  void parRequest_validScope_ResponseStatus_CREATED(final String scope) {

    Mockito.doNothing()
        .when(entityStatementRpService)
        .doAutoregistration(testHostUrl, testHostUrl + "/AS");

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
  @ParameterizedTest
  void parRequest_validAcrValue_ResponseStatus_CREATED(final String acr_value) {

    Mockito.doNothing()
        .when(entityStatementRpService)
        .doAutoregistration(testHostUrl, testHostUrl + "/AS");

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
            .field(
                "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
            .field("client_assertion", "TODO")
            .field("max_age", "0")
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
        .doAutoregistration(testHostUrl, testHostUrl + "/AS");

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
            .field(
                "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
            .field("client_assertion", "TODO")
            .field("max_age", "0")
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

    assertThat(respMsg7.getStatus()).isEqualTo(HttpStatus.FOUND);
  }

  @ValueSource(
      strings = {
          "urn:telematik:geburtsdatumurn:telematik:alter openid",
          "urn%3Atelematik%3Adisplay_name",
          "urn:telematik:given_name+openid",
          "urn:telematik:schlecht openid"
      })
  @ParameterizedTest
  void parRequest_invalidScope_ResponseStatus_BAD_REQUEST(final String scope) {
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
            .field(
                "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
            .field("client_assertion", "TODO")
            .field("max_age", "0")
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .asString();
    assertThat(resp.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
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
            .field(
                "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
            .field("client_assertion", "TODO")
            .field("max_age", "0")
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

  @Test
  void authRequest_missingClientId_ResponseStatus_BAD_REQUEST() {
    final HttpResponse<String> resp =
        Unirest.get(testHostUrl + FED_AUTH_ENDPOINT)
            .queryString("request_uri", "myInvalidRequestUri")
            .asString();
    assertThat(resp.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
  }

  /************************** FEDIDP_TOKEN_ENDPOINT *****************/
  @Test
  void tokenResponse_contains_httpStatus_400() {
    final HttpResponse<JsonNode> httpResponse =
        Unirest.post(testHostUrl + TOKEN_ENDPOINT)
            .field("grant_type", "authorization_code")
            .field("code", "DUMMY_CODE")
            .field("code_verifier", "DUMMY_CODE_VERIFIER")
            .field("client_id", "https://DUMMY_CLIENT.de")
            .field("redirect_uri", "DUMMY_REDIRECT_URI")
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .header(org.springframework.http.HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
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
            .header(org.springframework.http.HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
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

    final String KEY_ID = "ref_puk_fd_enc";
    // key from idp\idp-commons\src\test\resources\sig-nist.p12
    final String JWK_AS_STRING =
        "{\"use\": \"enc\",\"kid\": \"" + KEY_ID + "\",\"kty\": \"EC\",\"crv\": \"P-256\",\"x\":"
            + " \"Mq933FT_V8xd1TkfB0pH02d6cx2bmUS-bxHuBtA1yfs\",\"y\":"
            + " \"5uwf8phUbWIi92CqgglM94ft-FC4MHH836khswo6ppo\"}";

    Mockito.doNothing()
        .when(entityStatementRpService)
        .doAutoregistration(testHostUrl, testHostUrl + "/AS");

    Mockito.doReturn(PublicJsonWebKey.Factory.newPublicJwk(JWK_AS_STRING))
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
            .field(
                "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
            .field("client_assertion", "TODO")
            .field("max_age", "0")
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
            .header(jakarta.ws.rs.core.HttpHeaders.USER_AGENT, "IdP-Client")
            .header(org.springframework.http.HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
            .asJson();
    assertThat(httpResponse.getStatus()).isEqualTo(HttpStatus.OK);

    final String idTokenEncrypted = httpResponse.getBody().getObject().getString("id_token");
    final IdpJwe idpJwe = new IdpJwe(idTokenEncrypted);

    // verify that token is encrypted and check kid
    assertThat(idpJwe.extractHeaderClaims().get("kid")).isEqualTo(KEY_ID);
  }

  /**
   * Increase Test coverage of Landing page endpoint
   */
  @Test
  void parRequest_authRequestUriPar_invalidClientId_httpStatus_400() {
    Mockito.doNothing()
        .when(entityStatementRpService)
        .doAutoregistration(testHostUrl, testHostUrl + "/AS");

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
            .field(
                "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
            .field("client_assertion", "TODO")
            .field("max_age", "0")
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .asString();
    assertThat(respMsg3.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
  }

  /**
   * Increase Test coverage of Token endpoint
   */
  @Test
  void
  parRequest_authRequestUriPar_tokenRequest_invalidRedirectUri_invalidCodeVerifier_contains_httpStatus_400() {
    Mockito.doNothing()
        .when(entityStatementRpService)
        .doAutoregistration(testHostUrl, testHostUrl + "/AS");

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
            .field(
                "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
            .field("client_assertion", "TODO")
            .field("max_age", "0")
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
            .header(jakarta.ws.rs.core.HttpHeaders.USER_AGENT, "IdP-Client")
            .header(org.springframework.http.HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
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
            .header(jakarta.ws.rs.core.HttpHeaders.USER_AGENT, "IdP-Client")
            .header(org.springframework.http.HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
            .asJson();
    assertThat(httpResponse2.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
  }
}
