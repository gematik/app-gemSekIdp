/*
 * Copyright (c) 2023 gematik GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an 'AS IS' BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.idp.gsi.server.controller;

import static de.gematik.idp.IdpConstants.FACHDIENST_STATE_LENGTH;
import static de.gematik.idp.IdpConstants.FED_AUTH_APP_ENDPOINT;
import static de.gematik.idp.IdpConstants.TOKEN_ENDPOINT;
import static de.gematik.idp.gsi.server.controller.FedIdpController.URI_NONCE_LENGTH;
import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.idp.IdpConstants;
import de.gematik.idp.crypto.Nonce;
import de.gematik.idp.token.JsonWebToken;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import kong.unirest.HttpResponse;
import kong.unirest.HttpStatus;
import kong.unirest.JsonNode;
import kong.unirest.Unirest;
import org.apache.http.HttpHeaders;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.MediaType;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class FedIdpControllerTest {

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
          "request_object_signing_alg_values_supported",
          "id_token_signing_alg_values_supported",
          "id_token_encryption_alg_values_supported",
          "id_token_encryption_enc_values_supported",
          "user_type_supported");

  @LocalServerPort private int localServerPort;
  private String testHostUrl;
  private HttpResponse<String> responseGood;
  private JsonWebToken jwtInResponseGood;
  private Map<String, Object> bodyClaims;

  @BeforeAll
  void setup() {
    testHostUrl = "http://localhost:" + localServerPort;
    responseGood = retrieveEntityStatement();
    assertThat(responseGood.getStatus()).isEqualTo(HttpStatus.OK);
    jwtInResponseGood = new JsonWebToken(responseGood.getBody());
    bodyClaims = jwtInResponseGood.extractBodyClaims();
  }

  /************************** ENTITY_STATEMENT_ENDPOINT *****************/

  @Test
  void entityStatementResponse_ContentTypeEntityStatement() {
    assertThat(responseGood.getHeaders().get(HttpHeaders.CONTENT_TYPE).get(0))
        .isEqualTo("application/entity-statement+jwt;charset=UTF-8");
  }

  @Test
  void entityStatementResponse_JoseHeader() {
    assertThat(jwtInResponseGood.extractHeaderClaims()).containsOnlyKeys("typ", "alg", "kid");
  }

  @Test
  void entityStatement_BodyClaimsComplete() {
    assertThat(bodyClaims)
        .containsOnlyKeys("iss", "sub", "iat", "exp", "jwks", "authority_hints", "metadata");
  }

  @Test
  void entityStatement_ContainsJwks() {
    assertThat(bodyClaims.get("jwks")).isNotNull();
  }

  @Test
  void entityStatement_MetadataClaims() {
    final Map<String, Object> metadata = getInnerClaimMap(bodyClaims, "metadata");
    assertThat(metadata).containsOnlyKeys("openid_provider", "federation_entity");
  }

  @Test
  void entityStatement_OpenidProviderClaimsComplete() {
    final Map<String, Object> metadata = getInnerClaimMap(bodyClaims, "metadata");
    final Map<String, Object> openidProvider =
        Objects.requireNonNull(
            (Map<String, Object>) metadata.get("openid_provider"),
            "missing claim: openid_provider");

    assertThat(openidProvider).containsOnlyKeys(OPENID_PROVIDER_CLAIMS);
  }

  @SuppressWarnings("unchecked")
  @Test
  void entityStatement_OpenidProviderClaimsContentCorrect() {

    final Map<String, Object> metadata = getInnerClaimMap(bodyClaims, "metadata");
    final Map<String, Object> openidProvider =
        Objects.requireNonNull(
            (Map<String, Object>) metadata.get("openid_provider"),
            "missing claim: openid_provider");

    assertThat(openidProvider)
        .containsEntry("issuer", testHostUrl)
        .containsEntry("signed_jwks_uri", testHostUrl + "/jws.json");
    assertThat(openidProvider.get("organization_name")).asString().isNotEmpty();
    assertThat(openidProvider.get("logo_uri")).asString().isNotEmpty();
    assertThat(openidProvider)
        .containsEntry("authorization_endpoint", testHostUrl + "/auth")
        .containsEntry("token_endpoint", testHostUrl + "/token")
        .containsEntry("pushed_authorization_request_endpoint", testHostUrl + "/PAR_Auth");
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
            "urn:telematik:versicherter");
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

    // TODO: check content
    assertThat(openidProvider.get("user_type_supported").toString())
        .isIn(List.of("HCI", "HP", "IP"));
  }

  @SuppressWarnings("unchecked")
  @Test
  void entityStatement_FederationEntityClaimsContentCorrect() {
    final Map<String, Object> metadata = getInnerClaimMap(bodyClaims, "metadata");
    final Map<String, Object> federationEntity =
        Objects.requireNonNull(
            (Map<String, Object>) metadata.get("federation_entity"),
            "missing claim: federation_entity");

    assertThat(federationEntity)
        .containsEntry("name", "idp4711")
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

  /************************** FEDIDP_AUTH_ENDPOINT *****************/
  @ValueSource(
      strings = {"profile+telematik+openid", "telematik", "telematik+openid", "email+profile"})
  @ParameterizedTest
  void uriRequest_ResponseStatus_NOT_BAD_REQUEST(final String scope) {
    final HttpResponse<String> resp =
        Unirest.post(testHostUrl + IdpConstants.FED_AUTH_ENDPOINT)
            .field("client_id", testHostUrl)
            .field("state", "state_Fachdienst")
            .field("redirect_uri", testHostUrl + "/AS")
            .field("code_challenge", "P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk")
            .field("code_challenge_method", "S256")
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
    // due to missing states, we may receive HttpStatus.INTERNAL_SERVER_ERROR but not
    // HttpStatus.BAD_REQUEST
    assertThat(resp.getStatus()).isNotEqualTo(HttpStatus.BAD_REQUEST);
  }

  @Test
  void authRequest_MissingParameter() {
    final String requestUri =
        "urn:" + "https://Fachdienst007.de" + ":" + Nonce.getNonceAsHex(URI_NONCE_LENGTH);
    final String fachdienstState = Nonce.getNonceAsHex(FACHDIENST_STATE_LENGTH);

    final HttpResponse<String> resp =
        Unirest.post(testHostUrl + IdpConstants.FED_AUTH_ENDPOINT)
            .field("request_uri", requestUri)
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .asString();
    assertThat(resp.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
  }

  @Test
  void tokenResponse_contains_httpStatus_200() {
    final HttpResponse<JsonNode> httpResponse =
        Unirest.post(testHostUrl + TOKEN_ENDPOINT)
            .field("grant_type", "authorization_code")
            .field("code", "DUMMY_CODE")
            .field("code_verifier", "DUMMY_CODE_VERIFIER")
            .field("client_id", "https://DUMMY_CLIENT.de")
            .field("redirect_uri", "DUMMY_REDIRECT_URI")
            .field(
                "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
            .field("client_assertion", "TODO")
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .header(org.springframework.http.HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
            .asJson();
    assertThat(httpResponse.getStatus()).isEqualTo(org.springframework.http.HttpStatus.OK.value());
  }

  @Test
  void fedIdpAuthEndpoint() {
    final HttpResponse<String> resp =
        Unirest.post(testHostUrl + IdpConstants.FED_AUTH_ENDPOINT)
            .field("client_id", testHostUrl)
            .field("state", "state_Fachdienst")
            .field("redirect_uri", testHostUrl + "/AS")
            .field("code_challenge", "P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk")
            .field("code_challenge_method", "S256")
            .field("response_type", "code")
            .field("nonce", "42")
            .field("scope", "profile+telematik+openid")
            .field("acr_values", "gematik-ehealth-loa-high")
            .field(
                "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
            .field("client_assertion", "TODO")
            .field("max_age", "0")
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .asString();

    assertThat(resp.getStatus()).isEqualTo(HttpStatus.CREATED);

    final HttpResponse<JsonNode> httpResponse =
        Unirest.get(testHostUrl + FED_AUTH_APP_ENDPOINT)
            .queryString("request_uri", "DUMMY_REQUEST_URI")
            .header(org.springframework.http.HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
            .asJson();
    assertThat(httpResponse.getStatus())
        .isEqualTo(org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR.value());
  }
}
