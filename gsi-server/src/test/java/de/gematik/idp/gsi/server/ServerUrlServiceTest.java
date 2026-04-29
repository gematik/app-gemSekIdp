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

package de.gematik.idp.gsi.server;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static de.gematik.idp.gsi.server.common.Constants.ENTITY_STATEMENT_FED_MASTER;
import static de.gematik.idp.gsi.server.common.Constants.ENTITY_STMNT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2043;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import com.github.tomakehurst.wiremock.WireMockServer;
import de.gematik.idp.IdpConstants;
import de.gematik.idp.gsi.server.configuration.GsiConfiguration;
import de.gematik.idp.gsi.server.services.ServerUrlService;
import de.gematik.idp.token.JsonWebToken;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.HttpStatus;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.annotation.DirtiesContext.ClassMode;
import org.springframework.test.annotation.DirtiesContext.MethodMode;

@SpringBootTest(classes = GsiServer.class, webEnvironment = WebEnvironment.RANDOM_PORT)
@DirtiesContext(classMode = ClassMode.AFTER_CLASS)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ServerUrlServiceTest {

  public static final int MOCK_SERVER_PORT = 8086;
  private WireMockServer wireMockServer;

  @Autowired ServerUrlService serverUrlService;
  @Autowired GsiConfiguration gsiConfiguration;

  @BeforeAll
  void setup() {
    wireMockServer = new WireMockServer(MOCK_SERVER_PORT);
    wireMockServer.start();
    configureFor("localhost", MOCK_SERVER_PORT);
  }

  @AfterAll
  void teardown() {
    wireMockServer.stop();
  }

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
    stubFor(
        get(urlEqualTo(IdpConstants.ENTITY_STATEMENT_ENDPOINT))
            .willReturn(
                aResponse()
                    .withStatus(HttpStatus.OK.value())
                    .withHeader("Content-Type", "application/json")
                    .withBody(ENTITY_STATEMENT_FED_MASTER)));
    gsiConfiguration.setFedmasterUrl("http://localhost:" + MOCK_SERVER_PORT);
    assertThat(serverUrlService.determineFetchEntityStatementEndpoint())
        .isEqualTo("https://app-ref.federationmaster.de/federation/fetch");
  }

  @Test
  void testDetermineSignedJwksUri() {
    assertThat(
            ServerUrlService.determineSignedJwksUri(
                new JsonWebToken(ENTITY_STMNT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2043)))
        .contains("http://localhost:8084/jws.json");
  }
}
