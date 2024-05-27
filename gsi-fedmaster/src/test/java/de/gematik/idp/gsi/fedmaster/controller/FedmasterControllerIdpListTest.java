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
import de.gematik.idp.gsi.fedmaster.common.ConfigReader;
import de.gematik.idp.token.JsonWebToken;
import java.util.List;
import java.util.Map;
import kong.unirest.HttpResponse;
import kong.unirest.HttpStatus;
import kong.unirest.Unirest;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.HttpHeaders;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

@Slf4j
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class FedmasterControllerIdpListTest {

  @Autowired private ConfigReader configReader;
  @LocalServerPort private int localServerPort;
  private String testHostUrl;
  private HttpResponse<String> responseGood;
  private JsonWebToken jwtInResponseGood;
  private Map<String, Object> bodyClaims;

  @BeforeAll
  public void setup() {
    testHostUrl = "http://localhost:" + localServerPort;
    responseGood = retrieveIdpList();
    assertThat(responseGood.getStatus()).isEqualTo(HttpStatus.OK);
    jwtInResponseGood = new JsonWebToken(responseGood.getBody());
    bodyClaims = jwtInResponseGood.extractBodyClaims();
    log.info("testHostUrl: " + testHostUrl);
  }

  @Test
  void idpListResponse_ContentTypeJose() {
    assertThat(responseGood.getHeaders().get(HttpHeaders.CONTENT_TYPE).get(0))
        .isEqualTo("application/jwt;charset=UTF-8");
  }

  @Test
  void idpListResponse_JoseHeader() {
    assertThat(jwtInResponseGood.extractHeaderClaims()).containsOnlyKeys("typ", "alg", "kid");
  }

  @Test
  void entityListResponse_Alg() {
    assertThat(jwtInResponseGood.extractHeaderClaims()).containsEntry("alg", "ES256");
  }

  @Test
  void idpList_BodyClaimsComplete() {
    assertThat(bodyClaims).containsOnlyKeys("iss", "iat", "exp", "idp_entity");
  }

  @Test
  void entityList_firstEntry() {
    assertThat((List) bodyClaims.get("idp_entity")).hasSize(1);
    final Map<String, Object> claims =
        (Map<String, Object>) ((List) bodyClaims.get("idp_entity")).get(0);
    assertThat(claims)
        .containsEntry("organization_name", "GSI")
        .containsEntry("iss", configReader.getIdpIssByOrganizationName("GSI"));
  }

  @Test
  void idpList_BodyIsOfTypeJsonWebToken() {
    final JsonWebToken jwtInResponse = new JsonWebToken(responseGood.getBody());
    assertThat(jwtInResponse).isNotNull();
  }

  private HttpResponse<String> retrieveIdpList() {
    return Unirest.get(testHostUrl + IdpConstants.IDP_LIST_ENDPOINT).asString();
  }
}
