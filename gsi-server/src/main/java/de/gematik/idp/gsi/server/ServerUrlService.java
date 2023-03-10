/*
 * Copyright (c) 2023 gematik GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an 'AS IS' BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.idp.gsi.server;

import de.gematik.idp.gsi.server.configuration.GsiConfiguration;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.boot.web.servlet.context.ServletWebServerInitializedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class ServerUrlService {

  private final GsiConfiguration gsiConfiguration;
  private int serverPort;

  public int getServerPort() {
    return serverPort;
  }

  @EventListener
  public void onApplicationEvent(final ServletWebServerInitializedEvent event) {
    serverPort = event.getWebServer().getPort();
  }

  public String determineServerUrl() {
    return getServerUrlFromConfig()
        .orElse("Parameter \"gsi.serverUrl\" not found in configuration.");
  }

  private Optional<String> getServerUrlFromConfig() {
    return Optional.ofNullable(gsiConfiguration.getServerUrl()).filter(StringUtils::isNotBlank);
  }
}
