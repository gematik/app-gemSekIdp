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

package de.gematik.idp.gsi.server.logging;

import static de.gematik.idp.IdpConstants.FED_AUTH_ENDPOINT;
import static de.gematik.idp.IdpConstants.TOKEN_ENDPOINT;
import static de.gematik.idp.gsi.server.data.GsiConstants.FEDIDP_PAR_AUTH_ENDPOINT;

import com.google.gson.JsonObject;
import de.gematik.idp.gsi.server.configuration.GsiConfiguration;
import de.gematik.idp.gsi.server.services.HttpClient;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicReference;
import java.util.zip.CRC32;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@RequiredArgsConstructor
@Component
@ConditionalOnProperty(name = "gsi.bdeLoggingEnabled", havingValue = "true")
public class BdeLogger implements Filter {

  private static final int INTERNAL_GSI_ERROR_STATUS_CODE = 79000;
  private static final int THIRD_PARTY_ERROR_STATUS_CODE = 79111;

  private final AtomicReference<Queue<String>> logQueue =
      new AtomicReference<>(new ConcurrentLinkedQueue<>());
  private long startTimeOfLogging = System.currentTimeMillis();
  private final GsiConfiguration gsiConfiguration;

  @Scheduled(cron = "0 */5 * * * *")
  public void sendLogsToServer() {
    final Queue<String> oldQueue = logQueue.getAndSet(new ConcurrentLinkedQueue<>());
    final long endTimeOfLogging = System.currentTimeMillis();
    final String fileName =
        gsiConfiguration.getBdeCiId()
            + "_"
            + startTimeOfLogging
            + "_"
            + endTimeOfLogging
            + "_perf.log";
    startTimeOfLogging = endTimeOfLogging;
    HttpClient.sendLogsToBde(oldQueue, fileName, gsiConfiguration.getBdeEndpointUrl());
  }

  @Override
  public void doFilter(
      final ServletRequest request, final ServletResponse response, final FilterChain chain)
      throws IOException, ServletException {

    final long startTimeOfRequest = System.currentTimeMillis();

    chain.doFilter(request, response);

    final long duration = System.currentTimeMillis() - startTimeOfRequest;

    addLog(
        (HttpServletRequest) request, (HttpServletResponse) response, startTimeOfRequest, duration);
  }

  private void addLog(
      final HttpServletRequest httpServletRequest,
      final HttpServletResponse httpServletResponse,
      final long startTime,
      final long duration) {
    final String operationId = getOperationId(httpServletRequest.getRequestURI());
    if (operationId == null) {
      return;
    }
    if (operationId.equals("IDP.UC_31")) {
      if (httpServletRequest.getParameter("user_id") == null) {
        return;
      }
    }

    final JsonObject additionalInfo = new JsonObject();
    final String clientId = httpServletRequest.getParameter("client_id");
    if (clientId != null) {
      additionalInfo.addProperty("cidi", calculateCidi(clientId));
    }
    additionalInfo.addProperty("ik", gsiConfiguration.getBdeIkNumber());

    logQueue
        .get()
        .add(
            String.format(
                "%d;%d;%s;%d;%s",
                startTime,
                duration,
                operationId,
                getStatusCode(httpServletResponse.getStatus()),
                additionalInfo));
  }

  private Integer getStatusCode(final Integer statusCode) {
    if (statusCode >= 500) {
      return INTERNAL_GSI_ERROR_STATUS_CODE;
    } else if (statusCode >= 400) {
      return THIRD_PARTY_ERROR_STATUS_CODE;
    } else return statusCode;
  }

  private String getOperationId(final String path) {
    return switch (path) {
      case FEDIDP_PAR_AUTH_ENDPOINT -> "IDP.UC_30";
      case FED_AUTH_ENDPOINT -> "IDP.UC_31";
      case TOKEN_ENDPOINT -> "IDP.UC_39";
      default -> null;
    };
  }

  private Long calculateCidi(final String clientId) {
    final CRC32 crc32 = new CRC32();
    crc32.update(clientId.getBytes());
    return crc32.getValue();
  }
}
