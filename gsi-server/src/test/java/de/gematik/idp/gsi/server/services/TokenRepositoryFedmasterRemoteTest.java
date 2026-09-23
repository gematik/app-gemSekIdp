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

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.doThrow;

import de.gematik.idp.exceptions.IdpJwtSignatureInvalidException;
import de.gematik.idp.gsi.server.exceptions.GsiException;
import de.gematik.idp.token.JsonWebToken;
import java.security.PublicKey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class TokenRepositoryFedmasterRemoteTest {

  @Mock private ServerUrlService serverUrlService;
  @Mock private PublicKey fedmasterSigKey;
  @Mock private JsonWebToken jsonWebToken;
  @Mock private JsonWebToken newJsonWebToken;

  private TokenRepositoryFedmasterRemote repository;

  @BeforeEach
  void setUp() {
    repository = new TokenRepositoryFedmasterRemote(serverUrlService, fedmasterSigKey);
  }

  @Test
  void testFetchAndStoreEntityStmntAboutRpCalledWhenEntityStatementExpired() {
    final String sub = "test-sub";

    when(serverUrlService.determineFedmasterUrl()).thenReturn("http://fedmaster");
    when(serverUrlService.determineFetchEntityStatementEndpoint()).thenReturn("/entity-statement");
    when(newJsonWebToken.isExpired()).thenReturn(true);
    when(newJsonWebToken.getRawString()).thenReturn("jwt-token");

    try (final MockedStatic<HttpClient> httpClientMock = mockStatic(HttpClient.class)) {
      httpClientMock
          .when(() -> HttpClient.fetchEntityStatementAboutRp(anyString(), anyString(), anyString()))
          .thenReturn(newJsonWebToken);

      // First call to put one entity statement into the cache
      repository.getEntityStatementAboutRp(sub);

      // Second call to trigger the fetch because the one in the cache is expired
      repository.getEntityStatementAboutRp(sub);

      // Verify that fetchAndStoreEntityStmntAboutRp was called twice
      httpClientMock.verify(
          () ->
              HttpClient.fetchEntityStatementAboutRp(sub, "http://fedmaster", "/entity-statement"),
          times(2));
    }
  }

  @Test
  void testFetchAndStoreEntityStmntAboutRpNotCalledWhenEntityStatementNotExpired() {
    final String sub = "test-sub";

    when(jsonWebToken.isExpired()).thenReturn(false);
    when(jsonWebToken.getRawString()).thenReturn("jwt-token");
    when(serverUrlService.determineFedmasterUrl()).thenReturn("http://fedmaster");
    when(serverUrlService.determineFetchEntityStatementEndpoint()).thenReturn("/entity-statement");

    try (final MockedStatic<HttpClient> httpClientMock = mockStatic(HttpClient.class)) {
      httpClientMock
          .when(() -> HttpClient.fetchEntityStatementAboutRp(anyString(), anyString(), anyString()))
          .thenReturn(jsonWebToken);

      repository.getEntityStatementAboutRp(sub);
      repository.getEntityStatementAboutRp(sub);

      httpClientMock.verify(
          () ->
              HttpClient.fetchEntityStatementAboutRp(sub, "http://fedmaster", "/entity-statement"),
          times(1));
    }
  }

  @Test
  void testFetchAndStoreEntityStmntAboutRpThrowsExceptionOnInvalidSignature()
      throws IdpJwtSignatureInvalidException {
    final String sub = "test-sub";

    when(serverUrlService.determineFedmasterUrl()).thenReturn("http://fedmaster");
    when(serverUrlService.determineFetchEntityStatementEndpoint()).thenReturn("/entity-statement");
    doThrow(IdpJwtSignatureInvalidException.class).when(newJsonWebToken).verify(fedmasterSigKey);

    try (final MockedStatic<HttpClient> httpClientMock = mockStatic(HttpClient.class)) {
      httpClientMock
          .when(() -> HttpClient.fetchEntityStatementAboutRp(anyString(), anyString(), anyString()))
          .thenReturn(newJsonWebToken);

      org.junit.jupiter.api.Assertions.assertThrows(
          GsiException.class, () -> repository.getEntityStatementAboutRp(sub));
    }
  }
}
