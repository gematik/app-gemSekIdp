/*
 * Copyright (Date see Readme), gematik GmbH
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

package de.gematik.idp.gsi.fedmaster.controller;

import static de.gematik.idp.gsi.fedmaster.Constants.FEDMASTER_FEDERATION_FETCH_ENDPOINT;
import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.idp.gsi.fedmaster.common.ConfigReader;
import de.gematik.idp.token.JsonWebToken;
import java.util.Map;
import java.util.Objects;
import kong.unirest.core.HttpResponse;
import kong.unirest.core.HttpStatus;
import kong.unirest.core.Unirest;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpHeaders;

@Slf4j
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class FederationApiControllerTest {

  @Autowired private ConfigReader configReader;

  @LocalServerPort private int localServerPort;
  private String testHostUrl;
  private String fedMasterUrl;
  private String idpSektoralUrl;
  private String fachdienstUrl;

  @BeforeAll
  public void setup() {
    fedMasterUrl = configReader.getFedMasterUrl();
    testHostUrl = "http://localhost:" + localServerPort;
    fachdienstUrl = configReader.getRelyingPartyIssByOrganizationName("GRAS");
    idpSektoralUrl = configReader.getIdpIssByOrganizationName("GSI");
    log.info("testHostUrl: " + testHostUrl);
  }

  @Test
  void getEntityStatementFdResponse_HttpStatus200() {
    final HttpResponse response = retrieveEntityStatement(fachdienstUrl);
    assertThat(response.getStatus()).isEqualTo(HttpStatus.OK);
  }

  @Test
  void getEntityStatementIdpResponse_HttpStatus200() {
    final HttpResponse response = retrieveEntityStatement(idpSektoralUrl);
    assertThat(response.getStatus()).isEqualTo(HttpStatus.OK);
  }

  @Test
  void getEntityStatement_missingParams() {
    final HttpResponse response =
        Unirest.get(testHostUrl + FEDMASTER_FEDERATION_FETCH_ENDPOINT).asString();
    assertThat(response.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
    assertThat(response.getBody().toString()).contains("gematik_code\":\"-1");
  }

  @Test
  void getEntityStatement_emptySubParam() {
    final HttpResponse response = retrieveEntityStatement(null);
    assertThat(response.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
  }

  @Test
  void getEntityStatement_subNotFound() {
    final HttpResponse response = retrieveEntityStatement("https://invalid.sub");
    assertThat(response.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
    assertThat(response.getBody().toString()).contains("gematik_code\":\"6011");
  }

  @Test
  void getEntityStatement_contentTypeErrorMessage() {
    final HttpResponse response = retrieveEntityStatement("https://invalid.sub");
    assertThat(response.getHeaders().get(HttpHeaders.CONTENT_TYPE).get(0))
        .isEqualTo("application/json;charset=utf-8");
  }

  @Test
  void getEntityStatement_invalidIss() {

    final HttpResponse<String> response =
        Unirest.get(testHostUrl + FEDMASTER_FEDERATION_FETCH_ENDPOINT)
            .queryString("iss", "http://invalid.de")
            .queryString("sub", idpSektoralUrl)
            .asString();

    assertThat(response.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
    assertThat(response.getBody()).contains("\"operation\":\"FETCH\"");
    assertThat(response.getBody()).contains("\"error\":\"invalid_request\"");
    assertThat(response.getBody())
        .contains(
            "\"error_description\":\"Issuer entspricht nicht dem Entity Identifier des Federation"
                + " Masters\"");
    assertThat(response.getBody()).contains("\"gematik_timestamp\":");
    assertThat(response.getBody()).contains("\"gematik_uuid\":");
    assertThat(response.getBody()).contains("\"gematik_code\":\"6000\"}");
  }

  @Test
  void EntityStatementFdResponse_ContentTypeJose() {
    final HttpResponse response = retrieveEntityStatement(fachdienstUrl);
    assertThat(response.getHeaders().get(HttpHeaders.CONTENT_TYPE).get(0))
        .isEqualTo("application/entity-statement+jwt;charset=UTF-8");
  }

  @Test
  void EntityStatementIdpResponse_ContentTypeJose() {
    final HttpResponse response = retrieveEntityStatement(idpSektoralUrl);
    assertThat(response.getHeaders().get(HttpHeaders.CONTENT_TYPE).get(0))
        .isEqualTo("application/entity-statement+jwt;charset=UTF-8");
  }

  @Test
  void EntityStatementFdResponse_JoseHeader() {
    final JsonWebToken jwtInResponse = retrieveJwtFromEntityStatementFd();
    assertThat(jwtInResponse.extractHeaderClaims()).containsOnlyKeys("typ", "alg", "kid");
  }

  @Test
  void EntityStatementFd_ContainsJwks() {
    final JsonWebToken jwtInResponse = retrieveJwtFromEntityStatementFd();
    assertThat(jwtInResponse.extractBodyClaims().get("jwks")).isNotNull();
  }

  @Test
  void EntityStatementFd_ContainsSub() {
    final JsonWebToken jwtInResponse = retrieveJwtFromEntityStatementFd();
    assertThat(jwtInResponse.extractBodyClaims().get("sub")).isNotNull();
    assertThat(jwtInResponse.extractBodyClaims()).containsEntry("sub", fachdienstUrl);
  }

  @Test
  void EntityStatementIdp_ContainsSub() {
    final JsonWebToken jwtInResponse = retrieveJwtFromEntityStatementIdp();
    assertThat(jwtInResponse.extractBodyClaims().get("sub")).isNotNull();
    assertThat(jwtInResponse.extractBodyClaims()).containsEntry("sub", idpSektoralUrl);
  }

  @Test
  void EntityStatementFd_ContainsIss() {
    final JsonWebToken jwtInResponse = retrieveJwtFromEntityStatementFd();
    assertThat(jwtInResponse.extractBodyClaims().get("iss")).isNotNull();
    // Here "iss" is this FedMaster
    assertThat(jwtInResponse.extractBodyClaims()).containsEntry("iss", fedMasterUrl);
  }

  @Test
  void EntityStatementIdp_ContainsIss() {
    final JsonWebToken jwtInResponse = retrieveJwtFromEntityStatementIdp();
    assertThat(jwtInResponse.extractBodyClaims().get("iss")).isNotNull();
    assertThat(jwtInResponse.extractBodyClaims()).containsEntry("iss", fedMasterUrl);
  }

  @Test
  void EntityStatementFd_containsMetadata() {
    final JsonWebToken jwtInResponse = retrieveJwtFromEntityStatementFd();
    assertThat(jwtInResponse.extractBodyClaims().get("metadata")).isNotNull();
    final Map<String, Object> metadata =
        getInnerClaimMap(jwtInResponse.extractBodyClaims(), "metadata");
    assertThat(metadata).containsOnlyKeys("openid_relying_party");
    final Map<String, Object> openIdRelyingParty =
        getInnerClaimMap(metadata, "openid_relying_party");
    assertThat(openIdRelyingParty)
        .containsOnlyKeys("client_registration_types", "claims", "redirect_uris", "scope");
  }

  @Test
  void EntityStatemenIdp_containsMetadata() {
    final JsonWebToken jwtInResponse = retrieveJwtFromEntityStatementIdp();
    assertThat(jwtInResponse.extractBodyClaims().get("metadata")).isNotNull();
    final Map<String, Object> metadata =
        getInnerClaimMap(jwtInResponse.extractBodyClaims(), "metadata");
    assertThat(metadata).containsOnlyKeys("openid_provider");
    final Map<String, Object> openIdRelyingParty = getInnerClaimMap(metadata, "openid_provider");
    assertThat(openIdRelyingParty).containsOnlyKeys("client_registration_types_supported");
  }

  @Test
  void EntityStatement_MayContainAud() {
    final JsonWebToken entityStatement =
        new JsonWebToken(
            Unirest.get(testHostUrl + FEDMASTER_FEDERATION_FETCH_ENDPOINT)
                .queryString("iss", fedMasterUrl)
                .queryString("sub", idpSektoralUrl)
                .queryString("aud", fachdienstUrl)
                .asString()
                .getBody());
    assertThat(entityStatement.getBodyClaims()).containsEntry("aud", fachdienstUrl);
  }

  private JsonWebToken retrieveJwtFromEntityStatementFd() {
    return new JsonWebToken(retrieveEntityStatement(fachdienstUrl).getBody());
  }

  private JsonWebToken retrieveJwtFromEntityStatementIdp() {
    return new JsonWebToken(retrieveEntityStatement(idpSektoralUrl).getBody());
  }

  private HttpResponse<String> retrieveEntityStatement(final String sub) {
    return Unirest.get(testHostUrl + FEDMASTER_FEDERATION_FETCH_ENDPOINT)
        .queryString("iss", fedMasterUrl)
        .queryString("sub", sub)
        .asString();
  }

  private Map<String, Object> getInnerClaimMap(
      final Map<String, Object> claimMap, final String key) {
    return Objects.requireNonNull((Map<String, Object>) claimMap.get(key), "missing claim: " + key);
  }
}
