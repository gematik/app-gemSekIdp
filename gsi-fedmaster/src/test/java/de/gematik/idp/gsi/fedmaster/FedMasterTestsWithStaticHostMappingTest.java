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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import de.gematik.idp.gsi.fedmaster.configuration.FedMasterConfiguration;
import de.gematik.idp.gsi.fedmaster.services.StaticHostResolverProvider;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.net.spi.InetAddressResolverProvider;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

@ActiveProfiles({"localnet", "hostsmap"})
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class FedMasterTestsWithStaticHostMappingTest {

  @Autowired private FedMasterConfiguration fedMasterConfiguration;

  @Autowired FedMasterServer fedMasterServer;

  @Test
  void contextLoads() {
    assertThat(fedMasterConfiguration).isNotNull();
    final List<InetAddressResolverProvider> providers = new ArrayList<>();
    final ServiceLoader<InetAddressResolverProvider> loader =
        ServiceLoader.load(InetAddressResolverProvider.class);
    loader.forEach(providers::add);
    assertThat(providers).hasSize(1);
    final InetAddressResolverProvider provider = providers.getFirst();
    assertThat(provider).isInstanceOf(StaticHostResolverProvider.class);
    assertThat(provider.name()).isEqualTo("static hostname map");
  }

  @Test()
  @SneakyThrows({
    NoSuchFieldException.class,
    IllegalAccessException.class,
    NoSuchMethodException.class,
    InvocationTargetException.class
  })
  void checkEmptyMappings() {
    setMapping(null);
    getConfigureStaticHostResolverMethod().invoke(fedMasterServer);

    final var mapping = ""; // doesn't contain split character ,
    final Map<String, String> map =
        FedMasterServer.deserializeCommaSeparatedKeyValueMapping(mapping);
    assertThat(map).isNotNull().isEmpty();
  }

  @Test
  @SneakyThrows({
    NoSuchFieldException.class,
    IllegalAccessException.class,
    NoSuchMethodException.class,
    InvocationTargetException.class
  })
  void checkSimpleMapping() {
    final var mapping = "fedmaster.local=127.0.1.2,gsi.local=127.0.1.3";
    final Map<String, String> map =
        FedMasterServer.deserializeCommaSeparatedKeyValueMapping(mapping);
    assertThat(map)
        .isNotNull()
        .hasSize(2)
        .containsEntry("fedmaster.local", "127.0.1.2")
        .containsEntry("gsi.local", "127.0.1.3");
    setMapping(map);
    getConfigureStaticHostResolverMethod().invoke(fedMasterServer);
    assertThatCode(
            () -> {
              final InetAddress address = InetAddress.getByName("fedmaster.local");
              assertThat(address.getHostAddress()).isEqualTo("127.0.1.2");
            })
        .doesNotThrowAnyException();
    assertThatThrownBy(() -> InetAddress.getByName("shouldnotbearesolvablehostname.local"))
        .isInstanceOf(UnknownHostException.class)
        .hasMessageContaining("shouldnotbearesolvablehostname.local");
  }

  @Test
  void checkMappingSeparatorRobustness() {
    final var mapping = "fedmaster.local=127.0.1.2=127.0.1.3,gsi.local=";
    final Map<String, String> map =
        FedMasterServer.deserializeCommaSeparatedKeyValueMapping(mapping);
    // expect fedmaster.local mapping to be dropped because it has 3 parts (separated by =)
    // expect gsi.local mapping to be dropped because value is missing
    assertThat(map).isNotNull().isEmpty();
  }

  @Test
  @SneakyThrows({
    NoSuchFieldException.class,
    IllegalAccessException.class,
    NoSuchMethodException.class
  })
  void checkMappingIpAddressFormatError() {

    final var mapping = "fedmaster.local=256.0.1.2";
    final Map<String, String> map =
        FedMasterServer.deserializeCommaSeparatedKeyValueMapping(mapping);
    assertThat(map).isNotNull().hasSize(1);
    setMapping(map);
    Throwable t = null;
    try {
      getConfigureStaticHostResolverMethod().invoke(fedMasterServer);
    } catch (final InvocationTargetException e) {
      t = e.getTargetException();
    }
    assertThat(t)
        .isNotNull()
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Unable to parse IPaddress from mapping " + mapping + " ");
  }

  @Test
  @SneakyThrows({
    NoSuchFieldException.class,
    IllegalAccessException.class,
    NoSuchMethodException.class
  })
  void checkMappingIp6AddressFormatError() {

    final var mapping = "gsi.local=::-1";
    final Map<String, String> map =
        FedMasterServer.deserializeCommaSeparatedKeyValueMapping(mapping);
    assertThat(map).isNotNull().hasSize(1);
    setMapping(map);
    Throwable t = null;
    try {
      getConfigureStaticHostResolverMethod().invoke(fedMasterServer);
    } catch (final InvocationTargetException e) {
      t = e.getTargetException();
    }
    assertThat(t)
        .isNotNull()
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Unable to parse IPaddress from mapping " + mapping + " ");
  }

  private Method getConfigureStaticHostResolverMethod() throws NoSuchMethodException {
    final Method method = FedMasterServer.class.getDeclaredMethod("configureStaticHostResolver");
    method.setAccessible(true);
    return method;
  }

  private void setMapping(final Map<String, String> mapping)
      throws NoSuchFieldException, IllegalAccessException {
    final Field dnsMappings = FedMasterServer.class.getDeclaredField("dnsMappings");
    dnsMappings.setAccessible(true);
    dnsMappings.set(fedMasterServer, mapping);
  }
}
