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

import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.idp.IdpConstants;
import de.gematik.idp.gsi.server.GsiServer;
import de.gematik.idp.gsi.server.configuration.GsiConfiguration;
import de.gematik.idp.token.JsonWebToken;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import kong.unirest.core.HttpResponse;
import kong.unirest.core.HttpStatus;
import kong.unirest.core.Unirest;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpHeaders;

@Slf4j
@SpringBootTest(
    classes = GsiServer.class,
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class FedIdpControllerEntityStatementTest {

  @Autowired private GsiConfiguration gsiConfiguration;

  private String testHostUrl;
  @LocalServerPort private int serverPort;

  private HttpResponse<String> entityStatementResponseGood;
  private JsonWebToken entityStatement;
  private Map<String, Object> entityStatementbodyClaims;
  private Map<String, Object> metadataClaims;
  private Map<String, Object> openidProviderClaims;

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
          "claims_parameter_supported",
          "ti_features_supported");

  @SneakyThrows
  @BeforeAll
  void setup() {
    testHostUrl = "http://localhost:" + serverPort;
    entityStatementResponseGood = retrieveEntityStatement();
    assertThat(entityStatementResponseGood.getStatus()).isEqualTo(HttpStatus.OK);
    entityStatement = new JsonWebToken(entityStatementResponseGood.getBody());
    entityStatementbodyClaims = entityStatement.extractBodyClaims();
    metadataClaims = getInnerClaimMap(entityStatementbodyClaims, "metadata");
    openidProviderClaims = getInnerClaimMap(metadataClaims, "openid_provider");
  }

  @BeforeEach
  void init(final TestInfo testInfo) {
    log.info("START UNIT TEST: {}", testInfo.getDisplayName());
  }

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
    assertThat(entityStatementResponseGood.getHeaders().get(HttpHeaders.CONTENT_TYPE).getFirst())
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
    final Map<String, Object> metadata = metadataClaims;
    assertThat(metadata).containsOnlyKeys("openid_provider", "federation_entity");
  }

  @Test
  void test_entityStatement_OpenidProviderClaimsComplete() {
    final Map<String, Object> openidProvider = openidProviderClaims;
    assertThat(openidProvider).containsOnlyKeys(OPENID_PROVIDER_CLAIMS);
  }

  @SuppressWarnings("unchecked")
  @Test
  void test_entityStatement_OpenidProviderClaimsContentCorrect() {

    final String gsiServerUrl = gsiConfiguration.getServerUrl();
    final Map<String, Object> openidProvider = openidProviderClaims;

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
    assertThat((List<String>) openidProvider.get("client_registration_types_supported"))
        .containsExactlyInAnyOrder("automatic");
    assertThat((List<String>) openidProvider.get("subject_types_supported"))
        .hasSize(1)
        .isSubsetOf(List.of("pairwise", "public"));
    assertThat((List<String>) openidProvider.get("response_types_supported"))
        .containsExactlyInAnyOrder("code");
    assertThat((List<String>) openidProvider.get("scopes_supported"))
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
    assertThat((List<String>) openidProvider.get("response_modes_supported"))
        .containsExactlyInAnyOrder("query");
    assertThat((List<String>) openidProvider.get("grant_types_supported"))
        .containsExactlyInAnyOrder("authorization_code");
    assertThat((Boolean) openidProvider.get("require_pushed_authorization_requests")).isTrue();
    assertThat((List<String>) openidProvider.get("token_endpoint_auth_methods_supported"))
        .containsExactlyInAnyOrder("self_signed_tls_client_auth");
    assertThat(openidProvider.get("request_authentication_methods_supported"))
        .asString()
        .contains("ar", "par", "none", "self_signed_tls_client_auth");
    assertThat((List<String>) openidProvider.get("id_token_signing_alg_values_supported"))
        .containsExactlyInAnyOrder("ES256");
    assertThat((List<String>) openidProvider.get("id_token_encryption_alg_values_supported"))
        .containsExactlyInAnyOrder("ECDH-ES");
    assertThat((List<String>) openidProvider.get("id_token_encryption_enc_values_supported"))
        .containsExactlyInAnyOrder("A256GCM");
    assertThat((List<String>) openidProvider.get("user_type_supported"))
        .isSubsetOf(List.of("HCI", "HP", "IP"));
    assertThat(openidProvider.get("ti_features_supported"))
        .asString()
        .contains("id_token_version_supported");
  }

  @SuppressWarnings("unchecked")
  @Test
  void test_entityStatement_TiFeaturesSupportedCorrect() {
    final Map<String, Object> openidProvider = openidProviderClaims;

    final Map<String, Object> tiFeaturesSupported =
        getInnerClaimMap(openidProvider, "ti_features_supported");
    assertThat((List<String>) tiFeaturesSupported.get("id_token_version_supported"))
        .containsExactlyInAnyOrder("1.0.0", "2.0.0");
  }

  @Test
  void test_entityStatement_FederationEntityClaimsContentCorrect() {
    final Map<String, Object> federationEntity =
        getInnerClaimMap(metadataClaims, "federation_entity");
    final List<String> contacts = List.of("support@idp4711.de", "idm@gematik.de");
    assertThat(federationEntity)
        .containsEntry("name", "deprecated gematik sektoraler IDP")
        .containsEntry("organization_name", "gematik sektoraler IDP")
        .containsEntry("contacts", contacts)
        .containsEntry("homepage_uri", "https://idp4711.de");
  }
}
