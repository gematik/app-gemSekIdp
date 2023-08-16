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
import static de.gematik.idp.gsi.server.common.Constants.ENTITY_STMNT_IDP_FACHDIENST_EXPIRED;
import static de.gematik.idp.gsi.server.common.Constants.ENTITY_STMNT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2043;
import static de.gematik.idp.gsi.server.common.Constants.SIGNED_JWKS;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

import de.gematik.idp.IdpConstants;
import de.gematik.idp.crypto.CryptoLoader;
import de.gematik.idp.exceptions.IdpJwtExpiredException;
import de.gematik.idp.gsi.server.configuration.GsiConfiguration;
import de.gematik.idp.gsi.server.exceptions.GsiException;
import de.gematik.idp.token.JsonWebToken;
import java.io.File;
import java.io.IOException;
import java.security.PublicKey;
import java.util.Optional;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;
import org.jose4j.jwk.PublicJsonWebKey;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.mockserver.client.MockServerClient;
import org.mockserver.model.MediaType;
import org.mockserver.springtest.MockServerTest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.annotation.DirtiesContext.ClassMode;
import org.springframework.test.context.ActiveProfiles;

@Slf4j
@ActiveProfiles("test-entityservice")
@MockServerTest("server.url=http://localhost:${mockServerPort}")
@DirtiesContext(classMode = ClassMode.BEFORE_CLASS)
@SpringBootTest
class EntityStatementRpServiceTest {

  @Value("${server.url}")
  private String mockServerUrl;

  private MockServerClient mockServerClient;
  @Autowired EntityStatementRpService entityStatementRpService;
  @Autowired GsiConfiguration gsiConfiguration;
  @Autowired ServerUrlService serverUrlService;

  @Test
  void getEntityStatementRp() {
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
  void doAutoregistration() {
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
        () -> entityStatementRpService.doAutoregistration(mockServerUrl, correctRedirectUri));
  }

  @Test
  void verifyRedirectUriExistsInEntityStmnt() {
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
            () -> entityStatementRpService.doAutoregistration(mockServerUrl, nonExistingUri))
        .isInstanceOf(GsiException.class)
        .hasMessageContaining(
            "Content of parameter redirect_uri ["
                + nonExistingUri
                + "] not found in entity statement");
  }

  @Test
  void verifySignature_Token1Valid() throws IOException {
    final PublicKey publicKey =
        CryptoLoader.getCertificateFromPem(
                FileUtils.readFileToByteArray(
                    new File("src/test/resources/cert/fachdienst-sig.pem")))
            .getPublicKey();
    assertDoesNotThrow(
        () -> new JsonWebToken(ENTITY_STMNT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2043).verify(publicKey));
  }

  @Test
  void verifySignature_Token2Valid() throws IOException {
    final PublicKey publicKey =
        CryptoLoader.getCertificateFromPem(
                FileUtils.readFileToByteArray(
                    new File("src/test/resources/cert/fedmaster-sig-TU.pem")))
            .getPublicKey();
    assertDoesNotThrow(
        () ->
            new JsonWebToken(ENTITY_STMNT_ABOUT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2043)
                .verify(publicKey));
  }

  @Test
  void verifySignature_TokenExpired() throws IOException {
    final PublicKey publicKey =
        CryptoLoader.getCertificateFromPem(
                FileUtils.readFileToByteArray(
                    new File("src/test/resources/cert/fachdienst-sig.pem")))
            .getPublicKey();
    final JsonWebToken jsonWebTokenExpired = new JsonWebToken(ENTITY_STMNT_IDP_FACHDIENST_EXPIRED);
    assertThatThrownBy(() -> jsonWebTokenExpired.verify(publicKey))
        .isInstanceOf(IdpJwtExpiredException.class);
  }

  @SneakyThrows
  @Test
  void getEncKeyRpFromSignedJwks() {
    doAutoregistration();
    Mockito.doReturn(Optional.of(mockServerUrl + "/jws.json"))
        .when(serverUrlService)
        .determineSignedJwsUri(Mockito.any());
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
}
