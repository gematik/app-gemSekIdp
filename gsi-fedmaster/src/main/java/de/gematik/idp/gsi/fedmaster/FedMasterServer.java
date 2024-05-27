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

package de.gematik.idp.gsi.fedmaster;

import de.gematik.idp.gsi.fedmaster.configuration.FedMasterConfiguration;
import jakarta.annotation.PostConstruct;
import java.security.Security;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configurator;
import org.apache.logging.log4j.util.StackLocatorUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.web.filter.CommonsRequestLoggingFilter;

@Slf4j
@SpringBootApplication
@RequiredArgsConstructor
public class FedMasterServer {

  static {
    Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    Security.insertProviderAt(new BouncyCastleProvider(), 1);
  }

  @SuppressWarnings("java:S4823")
  public static void main(final String[] args) {
    SpringApplication.run(FedMasterServer.class, args);
  }

  private final FedMasterConfiguration fedMasterConfiguration;

  @PostConstruct
  public void setFedmasterLogLevel() {
    final String loglevel = fedMasterConfiguration.getLoglevel();
    final String loggerServer = "de.gematik.idp.gsi.fedmaster";
    final String loggerRequests = "org.springframework.web.filter.CommonsRequestLoggingFilter";
    Configurator.setLevel(loggerServer, loglevel);
    Configurator.setLevel(loggerRequests, loglevel);
    log.info("fedMasterConfiguration: {}", fedMasterConfiguration);

    final LoggerContext loggerContext =
        LoggerContext.getContext(StackLocatorUtil.getCallerClassLoader(2), false, null);
    log.info("loglevel: {}", loggerContext.getLogger(loggerServer).getLevel());
  }

  @Bean
  @ConditionalOnProperty(value = "fedmaster.debug.requestLogging")
  public CommonsRequestLoggingFilter requestLoggingFilter() {
    final CommonsRequestLoggingFilter loggingFilter = new CommonsRequestLoggingFilter();
    loggingFilter.setIncludeClientInfo(true);
    loggingFilter.setIncludeQueryString(true);
    loggingFilter.setIncludePayload(true);
    loggingFilter.setMaxPayloadLength(64000);
    loggingFilter.setIncludeHeaders(true);
    return loggingFilter;
  }
}
