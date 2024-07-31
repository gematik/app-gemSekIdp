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

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.net.spi.InetAddressResolver;
import java.net.spi.InetAddressResolverProvider;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Stream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implementation of java.net.spi.InetAddressResolverProvider Interface, so DNS Resolution within
 * jvm could be overridden without having to change Host settings.
 *
 * @deprecated duplicated code (in fedmaster/gsi-server/gras), possibly be moved to idp-commons
 *     after JAVA21 migration.
 */
@Deprecated(forRemoval = true)
public class StaticHostResolverProvider extends InetAddressResolverProvider {

  private static final Logger log = LoggerFactory.getLogger(StaticHostResolverProvider.class);

  private static final ConcurrentHashMap<String, InetAddress> map = new ConcurrentHashMap<>();

  @Override
  public InetAddressResolver get(final Configuration configuration) {

    log.debug("Handing out custom InetAddressResolver");

    return new InetAddressResolver() {

      final InetAddressResolver builtinResolver = configuration.builtinResolver();

      @Override
      public Stream<InetAddress> lookupByName(
          final String hostname, final LookupPolicy lookupPolicy) throws UnknownHostException {
        final InetAddress inetAddress = map.get(hostname);
        if (inetAddress != null) {
          log.debug(
              "Suppressing resolution of {} in favour of static address {}", hostname, inetAddress);
          return Stream.<InetAddress>builder().add(inetAddress).build();
        }
        return builtinResolver.lookupByName(hostname, lookupPolicy);
      }

      @Override
      public String lookupByAddress(final byte[] bytes) throws UnknownHostException {
        return builtinResolver.lookupByAddress(bytes);
      }
    };
  }

  @Override
  public String name() {
    return "static hostname map";
  }

  public static void setMapping(final String hostname, final InetAddress address) {
    log.info("Requested to override hostname resolution of {} to {}", hostname, address);
    map.put(hostname, address);
  }
}
