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

import static de.gematik.idp.gsi.server.data.GsiConstants.ASSET_LINKS_ENDPOINT_ANDROID;
import static de.gematik.idp.gsi.server.data.GsiConstants.ASSET_LINKS_ENDPOINT_IOS;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
@RequiredArgsConstructor
@Slf4j
public class AssetLinksController {

  private final ResourceLoader resourceLoader;

  @GetMapping(value = ASSET_LINKS_ENDPOINT_ANDROID)
  public ResponseEntity<Resource> getAssetLinksAndroid() {
    final Resource resource = resourceLoader.getResource("classpath:assetlinks.json");

    if (resource.exists()) {
      return ResponseEntity.ok(resource);
    } else {
      return ResponseEntity.notFound().build();
    }
  }

  @GetMapping(value = ASSET_LINKS_ENDPOINT_IOS, produces = "application/json")
  public ResponseEntity<Resource> getAssetLinksIos() {
    final Resource resource = resourceLoader.getResource("classpath:apple-app-site-association");

    if (resource.exists()) {
      return ResponseEntity.ok(resource);
    } else {
      return ResponseEntity.notFound().build();
    }
  }
}
