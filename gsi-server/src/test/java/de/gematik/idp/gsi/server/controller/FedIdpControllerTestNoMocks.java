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

package de.gematik.idp.gsi.server.controller;

import static de.gematik.idp.gsi.server.data.GsiConstants.FEDIDP_PAR_AUTH_ENDPOINT;
import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.idp.field.ClientUtilities;
import de.gematik.idp.field.CodeChallengeMethod;
import de.gematik.idp.gsi.server.GsiServer;
import kong.unirest.core.HttpResponse;
import kong.unirest.core.HttpStatus;
import kong.unirest.core.Unirest;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;

@Slf4j
@SpringBootTest(classes = GsiServer.class, webEnvironment = WebEnvironment.RANDOM_PORT)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class FedIdpControllerTestNoMocks {

  private String testHostUrl;
  @LocalServerPort private int serverPort;
  private String codeVerifier;
  private String redirectUri;

  @SneakyThrows
  @BeforeAll
  void setup() {
    testHostUrl = "http://localhost:" + serverPort;
    codeVerifier = ClientUtilities.generateCodeVerifier();
    redirectUri = testHostUrl + "/AS";
  }

  @SneakyThrows
  @Test
  void test_postPar_notRegisteredClientId_400() {
    final HttpResponse<String> response =
        Unirest.post(testHostUrl + FEDIDP_PAR_AUTH_ENDPOINT)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .field("client_id", "http://localhost:8084")
            .field("state", "state_Fachdienst")
            .field("redirect_uri", redirectUri)
            .field("code_challenge", ClientUtilities.generateCodeChallenge(codeVerifier))
            .field("code_challenge_method", CodeChallengeMethod.S256.toString())
            .field("response_type", "code")
            .field("nonce", "42")
            .field("scope", "urn:telematik:given_name openid")
            .field("acr_values", "gematik-ehealth-loa-high")
            .asString();

    assertThat(response.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST);

    assertThat(response.getBody()).contains("No entity statement about relying party");
  }
}
