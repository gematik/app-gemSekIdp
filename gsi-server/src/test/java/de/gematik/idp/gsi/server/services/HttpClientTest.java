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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

import de.gematik.idp.IdpConstants;
import de.gematik.idp.gsi.server.data.RpToken;
import de.gematik.idp.gsi.server.exceptions.GsiException;
import de.gematik.idp.token.JsonWebToken;
import javax.net.ssl.SSLException;
import kong.unirest.core.GetRequest;
import kong.unirest.core.HttpResponse;
import kong.unirest.core.Unirest;
import kong.unirest.core.UnirestException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class HttpClientTest {

  private static final String ANY_URL = "https://gsi.dev.therapy.app";
  private MockedStatic<Unirest> unirestMock;

  @BeforeEach
  void setUp() {
    unirestMock = mockStatic(Unirest.class);
  }

  @AfterEach
  void tearDown() {
    unirestMock.close();
  }

  @Test
  void test_fetchEntityStatementRpSSLException() {

    final GetRequest mockedRequest = mock(GetRequest.class);

    unirestMock
        .when(() -> Unirest.get(ANY_URL + IdpConstants.ENTITY_STATEMENT_ENDPOINT))
        .thenReturn(mockedRequest);

    when(mockedRequest.asString())
        .thenThrow(new UnirestException("SSL error", new SSLException("TLS handshake failed")));

    assertThatThrownBy(() -> HttpClient.fetchEntityStatementRp(ANY_URL))
        .isInstanceOf(GsiException.class)
        .hasMessageContaining(
            "SSL certificate validation failed for relying party ["
                + ANY_URL
                + "] available. Reason: SSL error")
        .hasCauseInstanceOf(UnirestException.class)
        .cause()
        .hasCauseInstanceOf(SSLException.class)
        .cause()
        .hasMessageContaining("TLS handshake failed");
  }

  @Test
  void test_fetchEntityStatementRpUnirestException() {

    final GetRequest mockedRequest = mock(GetRequest.class);

    unirestMock
        .when(() -> Unirest.get(ANY_URL + IdpConstants.ENTITY_STATEMENT_ENDPOINT))
        .thenReturn(mockedRequest);

    when(mockedRequest.asString()).thenThrow(new UnirestException("REST error"));

    assertThatThrownBy(() -> HttpClient.fetchEntityStatementRp(ANY_URL))
        .isInstanceOf(GsiException.class)
        .hasMessageContaining(
            "400 BAD_REQUEST \"Error when fetching entity statement of ["
                + ANY_URL
                + "]. Reason: REST error\"");
  }

  @Test
  void test_fetchEntityStatementRpHttp200() {

    final GetRequest mockedRequest = mock(GetRequest.class);
    final HttpResponse<String> mockedResponse = mock(HttpResponse.class);
    final String testSub = "sub42";
    final String testJson = "{\"some\": \"json\"}";

    unirestMock
        .when(() -> Unirest.get(ANY_URL + IdpConstants.ENTITY_STATEMENT_ENDPOINT))
        .thenReturn(mockedRequest);

    when(mockedResponse.getStatus()).thenReturn(200);
    when(mockedResponse.getBody()).thenReturn(testJson);

    when(mockedRequest.asString()).thenReturn(mockedResponse);

    final RpToken result = HttpClient.fetchEntityStatementRp(ANY_URL);

    assertThat(result).isNotNull();
  }

  @Test
  void test_fetchEntityStatementAboutRpHttp200() {

    final GetRequest mockedRequest = mock(GetRequest.class);
    final HttpResponse<String> mockedResponse = mock(HttpResponse.class);
    final String testSub = "sub42";
    final String testJson = "{\"some\": \"json\"}";

    unirestMock
        .when(() -> Unirest.get(ANY_URL + IdpConstants.ENTITY_STATEMENT_ENDPOINT))
        .thenReturn(mockedRequest);
    when(mockedRequest.queryString(eq("iss"), eq(ANY_URL))).thenReturn(mockedRequest);
    when(mockedRequest.queryString(eq("sub"), eq(testSub))).thenReturn(mockedRequest);

    when(mockedResponse.getStatus()).thenReturn(200);
    when(mockedResponse.getBody()).thenReturn(testJson);

    when(mockedRequest.asString()).thenReturn(mockedResponse);

    final JsonWebToken result =
        HttpClient.fetchEntityStatementAboutRp(
            testSub, ANY_URL, ANY_URL + IdpConstants.ENTITY_STATEMENT_ENDPOINT);

    assertThat(result).isNotNull();
    assertThat(result.getRawString()).isEqualTo(testJson);
  }

  @Test
  void test_fetchEntityStatementAboutRpHttp500() {

    final GetRequest mockedRequest = mock(GetRequest.class);
    final HttpResponse<String> mockedResponse = mock(HttpResponse.class);
    final String testSub = "sub42";
    final String testJson = "{\"some\": \"json\"}";

    unirestMock
        .when(() -> Unirest.get(ANY_URL + IdpConstants.ENTITY_STATEMENT_ENDPOINT))
        .thenReturn(mockedRequest);
    when(mockedRequest.queryString(eq("iss"), eq(ANY_URL))).thenReturn(mockedRequest);
    when(mockedRequest.queryString(eq("sub"), eq(testSub))).thenReturn(mockedRequest);

    when(mockedResponse.getStatus()).thenReturn(500);
    when(mockedResponse.getBody()).thenReturn(testJson);

    when(mockedRequest.asString()).thenReturn(mockedResponse);

    assertThatThrownBy(
            () ->
                HttpClient.fetchEntityStatementAboutRp(
                    testSub, ANY_URL, ANY_URL + IdpConstants.ENTITY_STATEMENT_ENDPOINT))
        .isInstanceOf(GsiException.class);
  }
}
