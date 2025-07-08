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

package de.gematik.idp.gsi.server.services;

import static de.gematik.idp.gsi.server.common.Constants.ENTITY_STMNT_ABOUT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2044;
import static de.gematik.idp.gsi.server.common.Constants.ENTITY_STMNT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2043;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;

import de.gematik.idp.gsi.server.configuration.GsiConfiguration;
import de.gematik.idp.gsi.server.data.RpToken;
import de.gematik.idp.gsi.server.exceptions.GsiException;
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

  private static final RpToken RPTOKEN_JWT_INVALID_SIG =
      new RpToken(
          new JsonWebToken(
              "eyJhbGciOiJFUzI1NiIsInR5cCI6ImVudGl0eS1zdGF0ZW1lbnQrand0Iiwia2lkIjoicHVrX2ZkX3NpZyJ9.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODQiLCJzdWIiOiJodHRwOi8vbG9jYWxob3N0OjgwODQiLCJpYXQiOjE3MDIwNTA0NTEsImV4cCI6MjMzMzIwMjQ1MSwiandrcyI6eyJrZXlzIjpbeyJ1c2UiOiJzaWciLCJraWQiOiJwdWtfZmRfc2lnIiwia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiI5YkpzMjdZQWZsTVVXSzVueHVpRjZYQUcwSmF6dXZ3UmkxRXBGSzBYS2lrIiwieSI6IlA4bHpOVlJPZ1R1d2JEcXNkOHJUMUFJM3plejk0SEJzVERwT3ZhalAwclkiLCJhbGciOiJFUzI1NiJ9XX0sImF1dGhvcml0eV9oaW50cyI6WyJodHRwczovL2FwcC10ZXN0LmZlZGVyYXRpb25tYXN0ZXIuZGUiXSwibWV0YWRhdGEiOnsib3BlbmlkX3JlbHlpbmdfcGFydHkiOnsic2lnbmVkX2p3a3NfdXJpIjoiaHR0cDovL2xvY2FsaG9zdDo4MDg0L2p3cy5qc29uIiwib3JnYW5pemF0aW9uX25hbWUiOiJGYWNoZGllbnN0MDA3IGRlcyBGZWRJZHAgUE9DcyIsImNsaWVudF9uYW1lIjoiRmFjaGRpZW5zdDAwNyIsImxvZ29fdXJpIjoiaHR0cDovL2xvY2FsaG9zdDo4MDg0L25vTG9nb1lldCIsInJlZGlyZWN0X3VyaXMiOlsiaHR0cHM6Ly9GYWNoZGllbnN0MDA3LmRlL2NsaWVudCIsImh0dHBzOi8vcmVkaXJlY3QudGVzdHN1aXRlLmdzaSIsImh0dHBzOi8vaWRwZmFkaS5kZXYuZ2VtYXRpay5zb2x1dGlvbnMvYXV0aCJdLCJyZXNwb25zZV90eXBlcyI6WyJjb2RlIl0sImNsaWVudF9yZWdpc3RyYXRpb25fdHlwZXMiOlsiYXV0b21hdGljIl0sImdyYW50X3R5cGVzIjpbImF1dGhvcml6YXRpb25fY29kZSJdLCJyZXF1aXJlX3B1c2hlZF9hdXRob3JpemF0aW9uX3JlcXVlc3RzIjp0cnVlLCJ0b2tlbl9lbmRwb2ludF9hdXRoX21ldGhvZCI6InNlbGZfc2lnbmVkX3Rsc19jbGllbnRfYXV0aCIsImRlZmF1bHRfYWNyX3ZhbHVlcyI6WyJnZW1hdGlrLWVoZWFsdGgtbG9hLWhpZ2giXSwiaWRfdG9rZW5fc2lnbmVkX3Jlc3BvbnNlX2FsZyI6IkVTMjU2IiwiaWRfdG9rZW5fZW5jcnlwdGVkX3Jlc3BvbnNlX2FsZyI6IkVDREgtRVMiLCJpZF90b2tlbl9lbmNyeXB0ZWRfcmVzcG9uc2VfZW5jIjoiQTI1NkdDTSIsInNjb3BlIjoidXJuOnRlbGVtYXRpazpkaXNwbGF5X25hbWUgdXJuOnRlbGVtYXRpazp2ZXJzaWNoZXJ0ZXIgb3BlbmlkIn0sImZlZGVyYXRpb25fZW50aXR5Ijp7Im5hbWUiOiJGYWNoZGllbnN0MDA3IiwiY29udGFjdHMiOlsiU3VwcG9ydEBGYWNoZGllbnN0MDA3LmRlIl0sImhvbWVwYWdlX3VyaSI6Imh0dHBzOi8vRmFjaGRpZW5zdDAwNy5kZSJ9fX0.XomqqjzmGfu3LFySjaKrfHcFStBK8pWW8uxH9HmNhdYoslBVd4z5t6I_DQQ2gbe5WWvKoGl0pVpGlGf5oIGR7Q"));

  private static final JsonWebToken JWT_ENTITY_STMNT_ABOUT_INVALID_SIG =
      new JsonWebToken(
          "eyJhbGciOiJFUzI1NiIsInR5cCI6ImVudGl0eS1zdGF0ZW1lbnQrand0Iiwia2lkIjoicHVrX2ZlZF9zaWcifQ.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwODMiLCJzdWIiOiJodHRwOi8vMTI3LjAuMC4xOjgwODQiLCJhdWQiOm51bGwsImlhdCI6MTczNTMwMjA4NiwiZXhwIjoyMzY2NDU0MDg2LCJqd2tzIjp7ImtleXMiOlt7InVzZSI6InNpZyIsImtpZCI6InB1a19mZF9zaWciLCJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IjliSnMyN1lBZmxNVVdLNW54dWlGNlhBRzBKYXp1dndSaTFFcEZLMFhLaWsiLCJ5IjoiUDhsek5WUk9nVHV3YkRxc2Q4clQxQUkzemV6OTRIQnNURHBPdmFqUDByWSIsImFsZyI6IkVTMjU2In1dfSwibWV0YWRhdGEiOnsib3BlbmlkX3JlbHlpbmdfcGFydHkiOnsiY2xpZW50X3JlZ2lzdHJhdGlvbl90eXBlcyI6WyJhdXRvbWF0aWMiXSwiY2xhaW1zIjpbXSwicmVkaXJlY3RfdXJpcyI6WyJodHRwOi8vMTI3LjAuMC4xOjgwODMvYXV0aCIsImh0dHBzOi8vRmFjaGRpZW5zdDAwNy5kZS9jbGllbnQiLCJodHRwczovL3JlZGlyZWN0LnRlc3RzdWl0ZS5nc2kiLCJodHRwczovL2lkcGZhZGkuZGV2LmdlbWF0aWsuc29sdXRpb25zL2F1dGgiXSwic2NvcGUiOiJ1cm46dGVsZW1hdGlrOmRpc3BsYXlfbmFtZSB1cm46dGVsZW1hdGlrOnZlcnNpY2hlcnRlciBvcGVuaWQifX19.fRJMg6ylrTIO3pPUItaxQD913Yj17cKQX1Eti91j9rFhKmwZvrNHFeYf-2iHdWASIxt2j1k5JUWrJ4LhckKLPQ");

  @Value("${server.url}")
  private String mockServerUrl;

  @BeforeEach
  void init(final TestInfo testInfo) {
    Mockito.doReturn(mockServerUrl + "/federation/fetch")
        .when(serverUrlService)
        .determineFetchEntityStatementEndpoint();
    httpClientMockedStatic = Mockito.mockStatic(HttpClient.class);

    httpClientMockedStatic
        .when(() -> HttpClient.fetchEntityStatementRp("http://any-client-id:8080"))
        .thenReturn(VALID_RPTOKEN);
    httpClientMockedStatic
        .when(() -> HttpClient.fetchEntityStatementRp("http://any-client-id:8080/invalidEsOfRp"))
        .thenReturn(RPTOKEN_JWT_INVALID_SIG);
    httpClientMockedStatic
        .when(
            () ->
                HttpClient.fetchEntityStatementAboutRp(
                    eq("http://any-client-id:8080"), any(), any()))
        .thenReturn(new JsonWebToken(ENTITY_STMNT_ABOUT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2044));
    httpClientMockedStatic
        .when(
            () ->
                HttpClient.fetchEntityStatementAboutRp(
                    eq("http://any-client-id:8080/invalidEsOfRp"), any(), any()))
        .thenReturn(new JsonWebToken(ENTITY_STMNT_ABOUT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2044));

    httpClientMockedStatic
        .when(
            () ->
                HttpClient.fetchEntityStatementAboutRp(
                    eq("http://any-client-id:8080/invalidEsAboutRP"), any(), any()))
        .thenReturn(JWT_ENTITY_STMNT_ABOUT_INVALID_SIG);
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
  void test_getEntityStatementRp_invalidSignature_INVALID() {

    assertThatThrownBy(
            () -> tokenRepositoryRp.getEntityStatementRp("http://any-client-id:8080/invalidEsOfRp"))
        .isInstanceOf(GsiException.class)
        .hasMessageContaining(
            "The JWT signature of the entity statement of the relying party was invalid.");
  }

  @Test
  void test_getEntityStatementAboutRp_Idpfachdienst_VALID() {
    final JsonWebToken entityStmntAboutFachdienst =
        tokenRepositoryRp.getEntityStatementAboutRp("http://any-client-id:8080");
    assertThat(entityStmntAboutFachdienst).isNotNull();
  }

  @Test
  void test_getEntityStatementAboutRp_Idpfachdienst_invalidSignature_INVALID() {

    assertThatThrownBy(
            () ->
                tokenRepositoryRp.getEntityStatementAboutRp(
                    "http://any-client-id:8080/invalidEsAboutRP"))
        .isInstanceOf(GsiException.class)
        .hasMessageContaining(
            "The JWT signature of the entity statement about the relying party was invalid.");
  }
}
