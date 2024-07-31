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

package de.gematik.idp.gsi.server.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import kong.unirest.core.HttpStatus;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;

@Slf4j
@ExtendWith(MockitoExtension.class)
class AssetLinksNegativeControllerTest {

  @Mock private ResourceLoader resourceLoader;
  @Mock private Resource resource;

  @InjectMocks private AssetLinksController assetLinksController;

  @Test
  void getAssetLinksAndroid_fileNotFound() {
    when(resourceLoader.getResource("classpath:assetlinks.json")).thenReturn(resource);
    when(resource.exists()).thenReturn(false);

    final ResponseEntity<Resource> responseEntity = assetLinksController.getAssetLinksAndroid();

    assertThat(responseEntity.getStatusCode())
        .isEqualTo(HttpStatusCode.valueOf(HttpStatus.NOT_FOUND));
  }

  @Test
  void getAssetLinksIos_fileNotFound() {
    when(resourceLoader.getResource("classpath:apple-app-site-association")).thenReturn(resource);
    when(resource.exists()).thenReturn(false);

    final ResponseEntity<Resource> responseEntity = assetLinksController.getAssetLinksIos();

    assertThat(responseEntity.getStatusCode())
        .isEqualTo(HttpStatusCode.valueOf(HttpStatus.NOT_FOUND));
  }
}
