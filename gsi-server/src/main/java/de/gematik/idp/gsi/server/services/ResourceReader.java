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

import de.gematik.idp.gsi.server.exceptions.GsiException;
import java.io.IOException;
import java.io.InputStream;
import lombok.RequiredArgsConstructor;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Service;
import org.springframework.util.StreamUtils;

@Service
@RequiredArgsConstructor
public class ResourceReader {

  private final ResourceLoader resourceLoader;

  public byte[] getFileFromResourceAsBytes(final String file) {
    final Resource resource = resourceLoader.getResource("classpath:" + file);
    try (final InputStream inputStream = resource.getInputStream()) {
      return StreamUtils.copyToByteArray(inputStream);
    } catch (final IOException e) {
      throw new GsiException("Error reading resource: " + file, e);
    }
  }
}
