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

import static de.gematik.idp.gsi.server.data.GsiConstants.FED_SIGNED_JWKS_ENDPOINT;
import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.idp.gsi.server.GsiServer;
import de.gematik.idp.token.JsonWebToken;
import java.util.List;
import java.util.Map;
import kong.unirest.core.HttpResponse;
import kong.unirest.core.Unirest;
import lombok.SneakyThrows;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpHeaders;

@SpringBootTest(
    classes = GsiServer.class,
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class FedIdpControllerSignedJwksTest {
  private String testHostUrl;
  @LocalServerPort private int serverPort;
  private HttpResponse<String> signedJwksResponseGood;
  private JsonWebToken signedJwks;

  @SneakyThrows
  @BeforeAll
  void setup() {
    testHostUrl = "http://localhost:" + serverPort;
    signedJwksResponseGood = retrieveSignedJwks();
    signedJwks = new JsonWebToken(signedJwksResponseGood.getBody());
  }

  private HttpResponse<String> retrieveSignedJwks() {
    return Unirest.get(testHostUrl + FED_SIGNED_JWKS_ENDPOINT).asString();
  }

  @Test
  void test_sigendJwksResponse_ContentTypeEntityStatement() {
    assertThat(signedJwksResponseGood.getHeaders().get(HttpHeaders.CONTENT_TYPE).getFirst())
        .isEqualTo("application/jwk-set+json;charset=UTF-8");
  }

  @Test
  void test_signedJwksResponse_JoseHeader() {
    assertThat(signedJwks.extractHeaderClaims()).containsOnlyKeys("typ", "alg", "kid");
  }

  @Test
  void test_signedJwksResponse_BodyClaims() {
    assertThat(signedJwks.extractBodyClaims()).containsOnlyKeys("keys", "iss", "iat");
  }

  @SuppressWarnings("unchecked")
  @Test
  void test_signedJwksResponse_Keys() {
    final List<Map<String, Object>> keyList =
        (List<Map<String, Object>>) signedJwks.getBodyClaims().get("keys");
    final List<Map<String, Object>> keyWithX5c =
        keyList.stream().filter(key -> key.containsKey("x5c")).toList();
    final List<Map<String, Object>> keyWithoutX5c =
        keyList.stream().filter(key -> !key.containsKey("x5c")).toList();
    assertThat(keyWithX5c).hasSize(1);
    assertThat(keyWithoutX5c).hasSize(1);
    assertThat(keyWithX5c.stream().findFirst().get().keySet())
        .containsExactlyInAnyOrder("use", "kid", "kty", "crv", "x", "y", "alg", "x5c");
    assertThat(keyWithoutX5c.stream().findFirst().get().keySet())
        .containsExactlyInAnyOrder("use", "kid", "kty", "crv", "x", "y", "alg");
  }
}
