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

import jakarta.annotation.PreDestroy;
import java.util.Queue;
import kong.unirest.core.HttpResponse;
import kong.unirest.core.Unirest;
import kong.unirest.core.UnirestInstance;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@ConditionalOnProperty(name = "gsi.bdeLoggingEnabled", havingValue = "true")
public class BdeHttpClient implements AutoCloseable {

  private final UnirestInstance client;

  public BdeHttpClient() {
    client = Unirest.spawnInstance();
    client.config().verifySsl(false);
  }

  public void sendLogsToBde(
      final Queue<String> logs, final String filename, final String bdeEndpointUrl) {
    final String logString = String.join("\n", logs);
    final HttpResponse<String> resp =
        client
            .post(bdeEndpointUrl)
            .header("Content-Type", "application/octet-stream")
            .header("Accept-Encoding", "gzip, deflate")
            .header("filename", filename)
            .body(logString.isEmpty() ? "leer" : logString)
            .asString();
    log.info("BDE response; status: " + resp.getStatus() + "; body: " + resp.getBody());
  }

  @Override
  @PreDestroy
  public void close() {
    client.close();
  }
}
