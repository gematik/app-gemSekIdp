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

package de.gematik.idp.gsi.server.configuration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;

import de.gematik.idp.data.KeyConfig;
import de.gematik.idp.gsi.server.KeyConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ResourceLoader;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.annotation.DirtiesContext.ClassMode;

@SpringBootTest
@DirtiesContext(classMode = ClassMode.AFTER_CLASS)
class GsiConfigurationTest {

  @Autowired GsiConfiguration gsiConfiguration;
  @Autowired ResourceLoader resourceLoader;

  @Test
  void fullIntTestComponent() {
    assertThat(gsiConfiguration).isNotNull();
    assertThat(gsiConfiguration.getEsSigPrivKeyConfig()).isNotNull();
    assertThat(gsiConfiguration.getTokenSigKeyConfig()).isNotNull();
  }

  @Test
  void testBuildComponent() {
    final GsiConfiguration gsiConfig =
        GsiConfiguration.builder()
            .esSigPrivKeyConfig(new KeyConfig("a", "b", "c", false))
            .tokenSigKeyConfig(new KeyConfig("g", "h", "i", true))
            .serverUrl("serverurl")
            .fedmasterSigPubKeyFilePath("anyCerts/myFedmasterSigCert.pem")
            .build();
    gsiConfig.setServerUrl("newUrl");
    assertThat(gsiConfig).isNotNull();
    assertThat(gsiConfig.getServerUrl()).isEqualTo("newUrl");
    assertThat(gsiConfig.getFedmasterSigPubKeyFilePath()).isNotNull();
    assertThat(gsiConfig.getEsSigPrivKeyConfig()).isNotNull();
    assertThat(GsiConfiguration.builder().toString()).hasSizeGreaterThan(0);

    assertThatThrownBy(() -> new KeyConfiguration(resourceLoader, gsiConfig).esSigPrivKey())
        .isInstanceOf(NullPointerException.class);
  }
}
