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

package de.gematik.idp.gsi.server;

import de.gematik.idp.gsi.server.configuration.GsiConfiguration;
import de.gematik.idp.gsi.server.services.StaticHostResolverProvider;
import jakarta.annotation.PostConstruct;
import java.io.IOException;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.Security;
import java.util.Arrays;
import java.util.Map;
import java.util.Map.Entry;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import javax.jmdns.JmDNS;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configurator;
import org.apache.logging.log4j.util.StackLocatorUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.web.filter.CommonsRequestLoggingFilter;

@Slf4j
@SpringBootApplication
@RequiredArgsConstructor
public class GsiServer {

  static {
    Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    Security.insertProviderAt(new BouncyCastleProvider(), 1);
  }

  @SuppressWarnings("java:S4823")
  public static void main(final String[] args) {
    SpringApplication.run(GsiServer.class, args);
  }

  @Value(
      "#{T(de.gematik.idp.gsi.server.GsiServer).deserializeCommaSeparatedKeyValueMapping('${hosts:}')}")
  private Map<String, String> dnsMappings;

  private final ApplicationContext context;
  private final GsiConfiguration gsiConfiguration;

  private JmDNS jmdns;

  @PostConstruct
  public void setGsiLogLevel() {
    final String loglevel = gsiConfiguration.getLoglevel();
    final String loggerServer = "de.gematik.idp.gsi.server";
    final String loggerRequests = "org.springframework.web.filter.CommonsRequestLoggingFilter";
    Configurator.setLevel(loggerServer, loglevel);
    Configurator.setLevel(loggerRequests, loglevel);
    log.info("gsiConfiguration: {}", gsiConfiguration);

    final LoggerContext loggerContext =
        LoggerContext.getContext(StackLocatorUtil.getCallerClassLoader(2), false, null);
    log.info("loglevel: {}", loggerContext.getLogger(loggerServer).getLevel());
    if (isSpringProfileActive("mdns")) {
      setupMDNS();
    }
    if (isSpringProfileActive("hostsmap")) {
      configureStaticHostResolver();
    } else {
      if (!dnsMappings.isEmpty()) {
        log.warn(
            "spring profile `hostsmap` is not active but host map is configured to {}",
            dnsMappings);
      }
    }
  }

  private boolean isSpringProfileActive(final String profileName) {
    return Arrays.asList(context.getEnvironment().getActiveProfiles()).contains(profileName);
  }

  private void configureStaticHostResolver() {
    if (dnsMappings == null) {
      return;
    }

    for (final Entry<String, String> elem : dnsMappings.entrySet()) {
      try {
        StaticHostResolverProvider.setMapping(
            elem.getKey(), InetAddress.getByName(elem.getValue()));
      } catch (final UnknownHostException e) {
        throw new IllegalArgumentException(
            "Unable to parse IPaddress from mapping "
                + elem.getKey()
                + "="
                + elem.getValue()
                + " ");
      }
    }
  }

  public static Map<String, String> deserializeCommaSeparatedKeyValueMapping(
      final String strValue) {
    return Pattern.compile(",")
        .splitAsStream(
            strValue
                .replaceAll("\\p{C}", "") // drop non printable characters
                .replaceAll("\\s+", "") // trim whitespaces
            )
        .map(elem -> elem.split("="))
        .filter(parts -> parts.length == 2)
        .collect(Collectors.toMap(parts -> parts[0], parts -> parts[1]));
  }

  /**
   * A multicast dns listener is configured with hostname part of gsi.serverUrl, so mdns requests
   * will be answered with ip/ipv6 address of the system running gsiServer.
   */
  private void setupMDNS() {
    try {
      final String hostname = readMdnsHostnameFromConfig();
      jmdns = JmDNS.create(null, hostname);
      log.info("Created mDNS listener for hostname: {}.local", hostname);
    } catch (final IOException e) {
      throw new RuntimeException("Error while creating jmdns instance", e);
    }
  }

  /** Checks configured gsi.serverUrl for `.local` domain suffix. */
  private String readMdnsHostnameFromConfig() {
    try {
      final URL url = new URI(gsiConfiguration.getServerUrl()).toURL();
      final String[] domainNameParts = url.getHost().split("\\.");
      if (domainNameParts.length == 2 && "local".equals(domainNameParts[1])) {
        return domainNameParts[0];
      } else {
        throw new RuntimeException("Configured serverUrl is not a valid multicast DNS name.");
      }
    } catch (final MalformedURLException | URISyntaxException e) {
      throw new RuntimeException(
          "Configured serverUrl is malformed: " + gsiConfiguration.getServerUrl(), e);
    }
  }

  @Bean
  @ConditionalOnProperty(value = "gsi.debug.requestLogging")
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
