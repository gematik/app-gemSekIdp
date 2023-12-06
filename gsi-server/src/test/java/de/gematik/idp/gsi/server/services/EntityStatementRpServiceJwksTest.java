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

package de.gematik.idp.gsi.server.services;

import static de.gematik.idp.gsi.server.common.Constants.ENTITY_STMNT_ABOUT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2043;
import static de.gematik.idp.gsi.server.common.Constants.ENTITY_STMNT_FACHDIENST_WITH_OPTIONAL_JWKS;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

import de.gematik.idp.IdpConstants;
import de.gematik.idp.gsi.server.GsiServer;
import de.gematik.idp.gsi.server.configuration.GsiConfiguration;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.jose4j.jwk.PublicJsonWebKey;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.mockserver.client.MockServerClient;
import org.mockserver.model.MediaType;
import org.mockserver.springtest.MockServerTest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.context.ActiveProfiles;

@Slf4j
@ActiveProfiles("test-entityservice")
@MockServerTest("server.url=http://localhost:${mockServerPort}")
@SpringBootTest(classes = GsiServer.class, webEnvironment = WebEnvironment.RANDOM_PORT)
class EntityStatementRpServiceJwksTest {

  @Value("${server.url}")
  private String mockServerUrl;

  private MockServerClient mockServerClient;
  @Autowired EntityStatementRpService entityStatementRpService;
  @Autowired GsiConfiguration gsiConfiguration;
  @Autowired ServerUrlService serverUrlService;

  @SneakyThrows
  @Test
  void getEncKeyRpFromEntityStatement() {
    prepareMocks();
    final PublicJsonWebKey rpEncKey = entityStatementRpService.getRpEncKey(mockServerUrl);
    assertThat(rpEncKey).isNotNull();
  }

  private void prepareMocks() {
    Mockito.doReturn(mockServerUrl + "/federation/fetch")
        .when(serverUrlService)
        .determineFetchEntityStatementEndpoint();
    mockServerClient
        .when(request().withMethod("GET").withPath(IdpConstants.ENTITY_STATEMENT_ENDPOINT))
        .respond(
            response()
                .withStatusCode(200)
                .withContentType(MediaType.APPLICATION_JSON)
                .withBody(ENTITY_STMNT_FACHDIENST_WITH_OPTIONAL_JWKS));
    mockServerClient
        .when(request().withMethod("GET").withPath("/federation/fetch"))
        .respond(
            response()
                .withStatusCode(200)
                .withContentType(MediaType.APPLICATION_JSON)
                .withBody(ENTITY_STMNT_ABOUT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2043));
  }
}
