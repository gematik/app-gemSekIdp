/*
 *  Copyright 2024 gematik GmbH
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

package de.gematik.idp.gsi.fedmaster.controller;

import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.idp.IdpConstants;
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
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpHeaders;

@Slf4j
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class FedmasterControllerEntStmntTest {

  @LocalServerPort private int localServerPort;
  private String testHostUrl;
  private HttpResponse<String> responseGood;
  private JsonWebToken jwtInResponseGood;
  private Map<String, Object> bodyClaims;

  @BeforeAll
  public void setup() {

    testHostUrl = "http://localhost:" + localServerPort;
    responseGood = retrieveEntityStatement();
    assertThat(responseGood.getStatus()).isEqualTo(HttpStatus.OK);
    jwtInResponseGood = new JsonWebToken(responseGood.getBody());
    bodyClaims = jwtInResponseGood.extractBodyClaims();
    log.info("testHostUrl: " + testHostUrl);
  }

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
  void entityStatementResponse_Alg() {
    assertThat(jwtInResponseGood.extractHeaderClaims()).containsEntry("alg", "ES256");
  }

  @Test
  void entityStatement_BodyClaimsComplete() {
    assertThat(bodyClaims).containsOnlyKeys("iss", "sub", "iat", "exp", "jwks", "metadata");
  }

  @Test
  void entityStatement_ContainsJwks() {
    assertThat(bodyClaims.get("jwks")).isNotNull();
  }

  @Test
  void entityStatement_MetadataClaims() {
    final Map<String, Object> metadata = getInnerClaimMap(bodyClaims, "metadata");
    assertThat(metadata).containsOnlyKeys("federation_entity");
    final Map<String, Object> federationEntity = getInnerClaimMap(metadata, "federation_entity");
    assertThat(federationEntity)
        .containsOnlyKeys(
            "federation_fetch_endpoint", "federation_list_endpoint", "idp_list_endpoint");
  }

  @Test
  void entityStatement_BodyIsOfTypeJsonWebToken() {
    final JsonWebToken jwtInResponse = new JsonWebToken(responseGood.getBody());
    assertThat(jwtInResponse).isNotNull();
  }

  @SuppressWarnings("unchecked")
  private Map<String, Object> getInnerClaimMap(
      final Map<String, Object> claimMap, final String key) {
    return Objects.requireNonNull((Map<String, Object>) claimMap.get(key), "missing claim: " + key);
  }

  private HttpResponse<String> retrieveEntityStatement() {
    return Unirest.get(testHostUrl + IdpConstants.ENTITY_STATEMENT_ENDPOINT).asString();
  }
}
