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

package de.gematik.idp.gsi.server.configuration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;

import de.gematik.idp.data.KeyConfig;
import de.gematik.idp.gsi.server.KeyConfiguration;
import de.gematik.idp.gsi.server.exceptions.GsiException;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ResourceLoader;

@SpringBootTest
class GsiConfigurationTest {

  @Autowired GsiConfiguration gsiConfiguration;
  @Autowired ResourceLoader resourceLoader;

  @Test
  void fullIntTestComponent() {
    assertThat(gsiConfiguration).isNotNull();
    assertThat(gsiConfiguration.getSigKeyConfig()).isNotNull();
    assertThat(gsiConfiguration.getTokenKeyConfig()).isNotNull();
  }

  @Test
  void testBuildComponent() {
    final GsiConfiguration gsiConfig =
        GsiConfiguration.builder()
            .sigKeyConfig(new KeyConfig("a", "b", "c", false))
            .tokenKeyConfig(new KeyConfig("d", "e", "f", false))
            .serverUrl("serverurl")
            .build();
    gsiConfig.setServerUrl("newUrl");
    assertThat(gsiConfig).isNotNull();
    assertThat(gsiConfig.getServerUrl()).isEqualTo("newUrl");
    assertThat(gsiConfig.getSigKeyConfig()).isNotNull();
    assertThat(gsiConfig.getTokenKeyConfig()).isNotNull();
    assertThat(GsiConfiguration.builder().toString()).hasSizeGreaterThan(0);

    assertThatThrownBy(
            () -> new KeyConfiguration(resourceLoader, gsiConfig).entityStatementSigKey())
        .isInstanceOf(GsiException.class);
  }
}
