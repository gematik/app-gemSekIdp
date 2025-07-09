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

import static de.gematik.idp.gsi.server.data.GsiConstants.ASSET_LINKS_ENDPOINT_ANDROID;
import static de.gematik.idp.gsi.server.data.GsiConstants.ASSET_LINKS_ENDPOINT_IOS;
import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.idp.gsi.server.GsiServer;
import kong.unirest.core.HttpResponse;
import kong.unirest.core.HttpStatus;
import kong.unirest.core.Unirest;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;

@Slf4j
@SpringBootTest(classes = GsiServer.class, webEnvironment = WebEnvironment.RANDOM_PORT)
class AssetLinksControllerTest {

  @LocalServerPort private int serverPort;

  @Test
  void test_getAssetLinksAndroid_200() {
    final String testHostUrl = "http://localhost:" + serverPort;
    final HttpResponse<String> resp =
        Unirest.get(testHostUrl + ASSET_LINKS_ENDPOINT_ANDROID).asString();
    assertThat(resp.getStatus()).isEqualTo(HttpStatus.OK);
  }

  @Test
  void test_getAssetLinksIos_200() {
    final String testHostUrl = "http://localhost:" + serverPort;
    final HttpResponse<String> resp =
        Unirest.get(testHostUrl + ASSET_LINKS_ENDPOINT_IOS).asString();
    assertThat(resp.getStatus()).isEqualTo(HttpStatus.OK);
  }
}
