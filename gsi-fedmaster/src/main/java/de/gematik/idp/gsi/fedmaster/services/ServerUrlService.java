/*
 *  Copyright 2024 gematik GmbH
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

package de.gematik.idp.gsi.fedmaster.services;

import de.gematik.idp.gsi.fedmaster.configuration.FedMasterConfiguration;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class ServerUrlService {

  private final FedMasterConfiguration fedMasterConfiguration;

  public String determineServerUrl() {
    return getServerUrlFromConfig()
        .orElse("Parameter \"fedmaster.serverUrl\" not found in configuration.");
  }

  private Optional<String> getServerUrlFromConfig() {
    return Optional.ofNullable(fedMasterConfiguration.getServerUrl())
        .filter(StringUtils::isNotBlank);
  }
}
