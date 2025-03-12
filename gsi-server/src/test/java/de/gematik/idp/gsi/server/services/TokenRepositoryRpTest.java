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

import static de.gematik.idp.gsi.server.common.Constants.ENTITY_STMNT_ABOUT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2044;
import static de.gematik.idp.gsi.server.common.Constants.ENTITY_STMNT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2043;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.ArgumentMatchers.any;

import de.gematik.idp.gsi.server.configuration.GsiConfiguration;
import de.gematik.idp.gsi.server.data.RpToken;
import de.gematik.idp.token.JsonWebToken;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockserver.client.MockServerClient;
import org.mockserver.springtest.MockServerTest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;

@MockServerTest("server.url=http://localhost:${mockServerPort}")
@SpringBootTest
class TokenRepositoryRpTest {

  private MockServerClient mockServerClient;
  @Autowired private TokenRepositoryRp tokenRepositoryRp;
  @Autowired GsiConfiguration gsiConfiguration;
  @MockBean private ServerUrlService serverUrlService;
  private static MockedStatic<HttpClient> httpClientMockedStatic;

  private static final RpToken VALID_RPTOKEN =
      new RpToken(new JsonWebToken(ENTITY_STMNT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2043));

  @Value("${server.url}")
  private String mockServerUrl;

  @BeforeEach
  void init(final TestInfo testInfo) {
    Mockito.doReturn(mockServerUrl + "/federation/fetch")
        .when(serverUrlService)
        .determineFetchEntityStatementEndpoint();
    httpClientMockedStatic = Mockito.mockStatic(HttpClient.class);

    httpClientMockedStatic
        .when(() -> HttpClient.fetchEntityStatementRp(any()))
        .thenReturn(VALID_RPTOKEN);
    httpClientMockedStatic
        .when(() -> HttpClient.fetchEntityStatementAboutRp(any(), any(), any()))
        .thenReturn(new JsonWebToken(ENTITY_STMNT_ABOUT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2044));
  }

  @AfterEach
  void tearDown() {
    httpClientMockedStatic.close();
  }

  @Test
  void test_getEntityStatementRp_VALID() {

    final RpToken entStmntFd = tokenRepositoryRp.getEntityStatementRp("http://any-client-id:8080");
    assertThat(entStmntFd).isNotNull();
  }

  @Test
  void test_getEntityStatementAboutRp_Idpfachdienst_VALID() {
    final JsonWebToken entityStmntAboutFachdienst =
        tokenRepositoryRp.getEntityStatementAboutRp("http://any-client-id:8080");
    assertThat(entityStmntAboutFachdienst).isNotNull();
  }
}
