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

package de.gematik.idp.gsi.server;

import de.gematik.idp.gsi.server.configuration.GsiConfiguration;
import jakarta.annotation.PostConstruct;
import java.security.Security;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.Logger;
import org.apache.logging.log4j.status.StatusLogger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.web.filter.CommonsRequestLoggingFilter;

@Slf4j
@SpringBootApplication
@RequiredArgsConstructor
@EnableScheduling
public class GsiServer {

  static {
    Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    Security.insertProviderAt(new BouncyCastleProvider(), 1);
  }

  @SuppressWarnings("java:S4823")
  public static void main(final String[] args) {
    SpringApplication.run(GsiServer.class, args);
  }

  private final GsiConfiguration gsiConfiguration;

  @PostConstruct
  public void printConfiguration() {
    log.info("GSI_CLIENT_CERT_REQUIRED in env: " + System.getenv("GSI_CLIENT_CERT_REQUIRED"));
    log.info("isClientCertRequired in config: " + gsiConfiguration.isClientCertRequired());
    log.info("gsiConfiguration: {}", gsiConfiguration);

    final Logger loggerGematik = (Logger) LogManager.getLogger("de.gematik");
    StatusLogger.getLogger()
        .log(
            org.apache.logging.log4j.Level.OFF,
            "loglevel for de.gematik: {}",
            loggerGematik.getLevel());
  }

  @Bean
  @ConditionalOnProperty(value = "logging.CommonsRequestLoggingEnabled", havingValue = "true")
  public CommonsRequestLoggingFilter requestLoggingFilter() {
    final CommonsRequestLoggingFilter loggingFilter = new CommonsRequestLoggingFilter();
    loggingFilter.setIncludeClientInfo(true);
    loggingFilter.setIncludeQueryString(true);
    loggingFilter.setIncludePayload(true);
    loggingFilter.setMaxPayloadLength(64000);
    loggingFilter.setIncludeHeaders(true);
    log.info("CommonsRequestLoggingFilter enabled");
    return loggingFilter;
  }
}
