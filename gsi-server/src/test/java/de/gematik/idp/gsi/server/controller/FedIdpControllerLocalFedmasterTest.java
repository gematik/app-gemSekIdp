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

import static de.gematik.idp.gsi.server.common.Constants.ENTITY_STMNT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2043;
import static de.gematik.idp.gsi.server.data.GsiConstants.FEDIDP_PAR_AUTH_ENDPOINT;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import de.gematik.idp.field.ClientUtilities;
import de.gematik.idp.field.CodeChallengeMethod;
import de.gematik.idp.gsi.server.GsiServer;
import de.gematik.idp.gsi.server.data.RpToken;
import de.gematik.idp.gsi.server.services.HttpClient;
import de.gematik.idp.gsi.server.services.TokenRepositoryFedmaster;
import de.gematik.idp.gsi.server.services.TokenRepositoryFedmasterLocal;
import de.gematik.idp.token.JsonWebToken;
import jakarta.servlet.http.HttpServletResponse;
import lombok.SneakyThrows;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

@SpringBootTest(
    classes = GsiServer.class,
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    properties = {"gsi.fedmasterMode=local"})
class FedIdpControllerLocalFedmasterTest {

  @Autowired private WebApplicationContext context;
  @Autowired private TokenRepositoryFedmaster tokenRepositoryFedmaster;
  @LocalServerPort private int serverPort;

  private MockMvc mockMvc;

  private static final RpToken VALID_RPTOKEN =
      new RpToken(new JsonWebToken(ENTITY_STMNT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2043));

  @BeforeEach
  void setup() {
    mockMvc = MockMvcBuilders.webAppContextSetup(context).build();
  }

  @Test
  @SneakyThrows
  void test_postPar_usesLocalFedmasterRepository() {
    assertThat(tokenRepositoryFedmaster).isInstanceOf(TokenRepositoryFedmasterLocal.class);

    try (final MockedStatic<HttpClient> httpClientMockedStatic =
        Mockito.mockStatic(HttpClient.class)) {
      httpClientMockedStatic
          .when(() -> HttpClient.fetchEntityStatementRp(anyString()))
          .thenReturn(VALID_RPTOKEN);

      final String redirectUri = "http://localhost:8085/AS";
      final String clientId = "http://localhost:8085";
      final String codeVerifier = ClientUtilities.generateCodeVerifier();
      final String codeChallenge = ClientUtilities.generateCodeChallenge(codeVerifier);

      final var response =
          mockMvc
              .perform(
                  post("http://localhost:" + serverPort + FEDIDP_PAR_AUTH_ENDPOINT)
                      .param("client_id", clientId)
                      .param("state", "state_Fachdienst")
                      .param("redirect_uri", redirectUri)
                      .param("code_challenge", codeChallenge)
                      .param("code_challenge_method", CodeChallengeMethod.S256.toString())
                      .param("response_type", "code")
                      .param("nonce", "42")
                      .param(
                          "scope", "openid urn:telematik:display_name urn:telematik:versicherter")
                      .param("acr_values", "gematik-ehealth-loa-high")
                      .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE))
              .andReturn()
              .getResponse();

      assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_CREATED);
      httpClientMockedStatic.verify(() -> HttpClient.fetchEntityStatementRp(anyString()));
      httpClientMockedStatic.verify(
          () -> HttpClient.fetchEntityStatementAboutRp(anyString(), any(), any()), never());
    }
  }
}
