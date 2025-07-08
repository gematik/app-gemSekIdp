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

package de.gematik.idp.gsi.fedmaster.controller;

import static de.gematik.idp.gsi.fedmaster.Constants.FED_LIST_ENDPOINT;
import static org.assertj.core.api.Assertions.assertThat;

import kong.unirest.core.HttpResponse;
import kong.unirest.core.HttpStatus;
import kong.unirest.core.Unirest;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpHeaders;

@Slf4j
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class FedmasterControllerFedListTest {

  @LocalServerPort private int localServerPort;

  private String testHostUrl;
  private HttpResponse<String> responseGood;

  private String jsonInResponseGood;

  @BeforeAll
  public void setup() {
    testHostUrl = "http://localhost:" + localServerPort;
    responseGood = retrieveFedList();
    jsonInResponseGood = responseGood.getBody();
    assertThat(responseGood.getStatus()).isEqualTo(HttpStatus.OK);
    log.info("testHostUrl: " + testHostUrl);
  }

  @Test
  void fedListResponse_ContentTypeJson() {
    assertThat(responseGood.getHeaders().get(HttpHeaders.CONTENT_TYPE).get(0))
        .isEqualTo("application/json;charset=UTF-8");
  }

  @Test
  void fedListResponse_BodyContent() {
    assertThat(jsonInResponseGood)
        .isEqualTo("[\"http://127.0.0.1:8084\",\"http://127.0.0.1:8085\"]");
  }

  private HttpResponse<String> retrieveFedList() {
    return Unirest.get(testHostUrl + FED_LIST_ENDPOINT).asString();
  }
}
