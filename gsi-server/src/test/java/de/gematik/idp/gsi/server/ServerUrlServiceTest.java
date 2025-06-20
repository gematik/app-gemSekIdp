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

package de.gematik.idp.gsi.server;

import static de.gematik.idp.gsi.server.common.Constants.ENTITY_STATEMENT_FED_MASTER;
import static de.gematik.idp.gsi.server.common.Constants.ENTITY_STMNT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2043;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

import de.gematik.idp.IdpConstants;
import de.gematik.idp.gsi.server.configuration.GsiConfiguration;
import de.gematik.idp.gsi.server.services.ServerUrlService;
import de.gematik.idp.token.JsonWebToken;
import org.junit.jupiter.api.Test;
import org.mockserver.client.MockServerClient;
import org.mockserver.model.MediaType;
import org.mockserver.springtest.MockServerTest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.annotation.DirtiesContext.ClassMode;
import org.springframework.test.annotation.DirtiesContext.MethodMode;

@SpringBootTest(classes = GsiServer.class, webEnvironment = WebEnvironment.RANDOM_PORT)
@DirtiesContext(classMode = ClassMode.AFTER_CLASS)
@MockServerTest("server.url=http://localhost:${mockServerPort}")
class ServerUrlServiceTest {

  @Value("${server.url}")
  private String mockServerUrl;

  @Autowired ServerUrlService serverUrlService;
  @Autowired GsiConfiguration gsiConfiguration;
  private MockServerClient mockServerClient;

  @Test
  void testDetermineServerUrl() {
    assertThat(serverUrlService.determineServerUrl()).contains("gsi.dev.gematik.solutions");
  }

  @Test
  void testFedmasterServerUrl() {
    assertThat(serverUrlService.determineFedmasterUrl())
        .isEqualTo("https://app-test.federationmaster.de");
  }

  @DirtiesContext(methodMode = MethodMode.BEFORE_METHOD)
  @Test
  void testDetermineFetchEntityStatementEndpoint() {
    mockServerClient
        .when(request().withMethod("GET").withPath(IdpConstants.ENTITY_STATEMENT_ENDPOINT))
        .respond(
            response()
                .withStatusCode(200)
                .withContentType(MediaType.APPLICATION_JSON)
                .withBody(ENTITY_STATEMENT_FED_MASTER));
    gsiConfiguration.setFedmasterUrl(mockServerUrl);
    assertThat(serverUrlService.determineFetchEntityStatementEndpoint())
        .isEqualTo("https://app-ref.federationmaster.de/federation/fetch");
  }

  @Test
  void testDetermineSignedJwksUri() {
    assertThat(
            serverUrlService.determineSignedJwksUri(
                new JsonWebToken(ENTITY_STMNT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2043)))
        .contains("http://localhost:8084/jws.json");
  }
}
