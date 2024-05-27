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
import static de.gematik.idp.gsi.server.common.Constants.ENTITY_STMNT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2043;
import static de.gematik.idp.gsi.server.common.Constants.SIGNED_JWKS;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

import de.gematik.idp.IdpConstants;
import de.gematik.idp.gsi.server.GsiServer;
import de.gematik.idp.gsi.server.configuration.GsiConfiguration;
import de.gematik.idp.gsi.server.exceptions.GsiException;
import de.gematik.idp.token.JsonWebToken;
import java.util.Optional;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.jose4j.jwk.PublicJsonWebKey;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mockito;
import org.mockserver.client.MockServerClient;
import org.mockserver.model.MediaType;
import org.mockserver.springtest.MockServerTest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.annotation.DirtiesContext.ClassMode;
import org.springframework.test.context.ActiveProfiles;

@Slf4j
@ActiveProfiles("test-entityservice")
@MockServerTest("server.url=http://localhost:${mockServerPort}")
@DirtiesContext(classMode = ClassMode.AFTER_CLASS)
@SpringBootTest(classes = GsiServer.class, webEnvironment = WebEnvironment.RANDOM_PORT)
class EntityStatementRpServiceTest {

  @Value("${server.url}")
  private String mockServerUrl;

  private MockServerClient mockServerClient;
  @Autowired EntityStatementRpService entityStatementRpService;
  @Autowired GsiConfiguration gsiConfiguration;
  @Autowired ServerUrlService serverUrlService;

  @Test
  void getEntityStatementRp() {
    Mockito.doReturn(mockServerUrl + "/federation/fetch")
        .when(serverUrlService)
        .determineFetchEntityStatementEndpoint();
    mockServerClient
        .when(request().withMethod("GET").withPath(IdpConstants.ENTITY_STATEMENT_ENDPOINT))
        .respond(
            response()
                .withStatusCode(200)
                .withContentType(MediaType.APPLICATION_JSON)
                .withBody(ENTITY_STMNT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2043));
    mockServerClient
        .when(request().withMethod("GET").withPath("/federation/fetch"))
        .respond(
            response()
                .withStatusCode(200)
                .withContentType(MediaType.APPLICATION_JSON)
                .withBody(ENTITY_STMNT_ABOUT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2043));
    gsiConfiguration.setFedmasterUrl(mockServerUrl);
    final JsonWebToken entStmntFd = entityStatementRpService.getEntityStatementRp(mockServerUrl);
    assertThat(entStmntFd).isNotNull();
  }

  @Test
  void getEntityStatementAboutRp_Idpfachdienst() {
    Mockito.doReturn(mockServerUrl + "/federation/fetch")
        .when(serverUrlService)
        .determineFetchEntityStatementEndpoint();
    mockServerClient
        .when(request().withMethod("GET").withPath("/federation/fetch"))
        .respond(
            response()
                .withStatusCode(200)
                .withContentType(MediaType.APPLICATION_JSON)
                .withBody(ENTITY_STMNT_ABOUT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2043));
    // switch configuration to mockserver
    gsiConfiguration.setFedmasterUrl(mockServerUrl);
    final JsonWebToken entityStmntAboutFachdienst =
        entityStatementRpService.getEntityStatementAboutRp("dummyUrl");
    assertThat(entityStmntAboutFachdienst).isNotNull();
  }

  @Test
  void verifyRedirectUriExistsInEntityStmnt() {
    Mockito.doReturn(mockServerUrl + "/federation/fetch")
        .when(serverUrlService)
        .determineFetchEntityStatementEndpoint();
    mockServerClient
        .when(request().withMethod("GET").withPath(IdpConstants.ENTITY_STATEMENT_ENDPOINT))
        .respond(
            response()
                .withStatusCode(200)
                .withContentType(MediaType.APPLICATION_JSON)
                .withBody(ENTITY_STMNT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2043));
    mockServerClient
        .when(request().withMethod("GET").withPath("/federation/fetch"))
        .respond(
            response()
                .withStatusCode(200)
                .withContentType(MediaType.APPLICATION_JSON)
                .withBody(ENTITY_STMNT_ABOUT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2043));
    gsiConfiguration.setFedmasterUrl(mockServerUrl);
    final String nonExistingUri = "nonExistingUri";
    assertThatThrownBy(
            () ->
                entityStatementRpService.doAutoregistration(
                    mockServerUrl, nonExistingUri, "urn:telematik:versicherter openid"))
        .isInstanceOf(GsiException.class)
        .hasMessageContaining(
            "Content of parameter redirect_uri ["
                + nonExistingUri
                + "] not found in entity statement");
  }

  @SneakyThrows
  @Test
  void getEncKeyRpFromSignedJwks() {
    Mockito.doReturn(mockServerUrl + "/federation/fetch")
        .when(serverUrlService)
        .determineFetchEntityStatementEndpoint();
    Mockito.doReturn(Optional.of(mockServerUrl + "/jws.json"))
        .when(serverUrlService)
        .determineSignedJwksUri(Mockito.any());
    mockServerClient
        .when(request().withMethod("GET").withPath(IdpConstants.ENTITY_STATEMENT_ENDPOINT))
        .respond(
            response()
                .withStatusCode(200)
                .withContentType(MediaType.APPLICATION_JSON)
                .withBody(ENTITY_STMNT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2043));
    mockServerClient
        .when(request().withMethod("GET").withPath("/federation/fetch"))
        .respond(
            response()
                .withStatusCode(200)
                .withContentType(MediaType.APPLICATION_JSON)
                .withBody(ENTITY_STMNT_ABOUT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2043));
    mockServerClient
        .when(request().withMethod("GET").withPath("/jws.json"))
        .respond(
            response()
                .withStatusCode(200)
                .withContentType(new MediaType("application", "entity-statement+jwt"))
                .withBody(SIGNED_JWKS));
    gsiConfiguration.setFedmasterUrl(mockServerUrl);
    final PublicJsonWebKey rpEncKey = entityStatementRpService.getRpEncKey(mockServerUrl);
    assertThat(rpEncKey).isNotNull();
  }

  @Test
  void relyingPartyAutoregistration() {
    Mockito.doReturn(mockServerUrl + "/federation/fetch")
        .when(serverUrlService)
        .determineFetchEntityStatementEndpoint();
    mockServerClient
        .when(request().withMethod("GET").withPath(IdpConstants.ENTITY_STATEMENT_ENDPOINT))
        .respond(
            response()
                .withStatusCode(200)
                .withContentType(MediaType.APPLICATION_JSON)
                .withBody(ENTITY_STMNT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2043));
    mockServerClient
        .when(request().withMethod("GET").withPath("/federation/fetch"))
        .respond(
            response()
                .withStatusCode(200)
                .withContentType(MediaType.APPLICATION_JSON)
                .withBody(ENTITY_STMNT_ABOUT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2043));
    gsiConfiguration.setFedmasterUrl(mockServerUrl);
    final String correctRedirectUri = "https://redirect.testsuite.gsi";
    assertDoesNotThrow(
        () ->
            entityStatementRpService.doAutoregistration(
                mockServerUrl, correctRedirectUri, "urn:telematik:versicherter openid"));
  }

  @ValueSource(
      strings = {
        "urn:telematik:geburtsdatumurn:telematik:alter openid",
        "urn%3Atelematik%3Adisplay_name",
        "urn:telematik:given_name+openid",
        "urn:telematik:schlecht openid"
      })
  @ParameterizedTest(name = "checkException_verifyInvalidScopes scope: {0}")
  void checkException_verifyInvalidScopes(final String scope) {
    Mockito.doReturn(mockServerUrl + "/federation/fetch")
        .when(serverUrlService)
        .determineFetchEntityStatementEndpoint();
    mockServerClient
        .when(request().withMethod("GET").withPath(IdpConstants.ENTITY_STATEMENT_ENDPOINT))
        .respond(
            response()
                .withStatusCode(200)
                .withContentType(MediaType.APPLICATION_JSON)
                .withBody(ENTITY_STMNT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2043));
    mockServerClient
        .when(request().withMethod("GET").withPath("/federation/fetch"))
        .respond(
            response()
                .withStatusCode(200)
                .withContentType(MediaType.APPLICATION_JSON)
                .withBody(ENTITY_STMNT_ABOUT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2043));
    gsiConfiguration.setFedmasterUrl(mockServerUrl);
    assertThatThrownBy(
            () ->
                entityStatementRpService.doAutoregistration(
                    mockServerUrl, "https://redirect.testsuite.gsi", scope))
        .isInstanceOf(GsiException.class)
        .hasMessageContaining(
            "Content of parameter scope [" + scope + "] exceeds scopes found in entity statement.");
  }
}
