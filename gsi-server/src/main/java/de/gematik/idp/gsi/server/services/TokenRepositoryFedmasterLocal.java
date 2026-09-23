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

import de.gematik.idp.gsi.server.configuration.GsiConfiguration;
import de.gematik.idp.token.JsonWebToken;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

@Slf4j
@Service
@ConditionalOnProperty(prefix = "gsi", name = "fedmasterMode", havingValue = "local")
@RequiredArgsConstructor
public class TokenRepositoryFedmasterLocal implements TokenRepositoryFedmaster {

  private final GsiConfiguration gsiConfiguration;
  private JsonWebToken entityStatementAboutRp;

  @Override
  public JsonWebToken getEntityStatementAboutRp(final String sub) {
    if (entityStatementAboutRp == null) {
      entityStatementAboutRp = new JsonWebToken(loadEntityStatementAboutRpFromConfiguration());
      log.info(
          "Loaded local entity statement about relying party for [{}] from [{}]",
          sub,
          gsiConfiguration.getFedmasterLocalEntityStatementFile());
    }
    return entityStatementAboutRp;
  }

  private String loadEntityStatementAboutRpFromConfiguration() {
    final String configuredPath = gsiConfiguration.getFedmasterLocalEntityStatementFile();
    if (!StringUtils.hasText(configuredPath)) {
      throw new IllegalStateException(
          "gsi.fedmasterLocalEntityStatementFile must be configured when gsi.fedmasterMode=local");
    }

    try {
      if (configuredPath.startsWith("classpath:")) {
        final var resource = new ClassPathResource(configuredPath.substring("classpath:".length()));
        try (final var inputStream = resource.getInputStream()) {
          return new String(inputStream.readAllBytes(), StandardCharsets.UTF_8).trim();
        }
      }
      return Files.readString(Path.of(configuredPath), StandardCharsets.UTF_8).trim();
    } catch (final IOException e) {
      throw new IllegalStateException(
          "Unable to load local entity statement about relying party from " + configuredPath, e);
    }
  }
}
