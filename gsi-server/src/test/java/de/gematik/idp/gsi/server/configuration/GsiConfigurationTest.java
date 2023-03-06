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
  }

  @Test
  void testBuildComponent() {
    final GsiConfiguration gsiConfig =
        GsiConfiguration.builder()
            .sigKeyConfig(new KeyConfig("a", "b", "c", false))
            .serverUrl("serverurl")
            .build();
    gsiConfig.setServerUrl("newUrl");
    assertThat(gsiConfig).isNotNull();
    assertThat(gsiConfig.getServerUrl()).isEqualTo("newUrl");
    assertThat(gsiConfig.getSigKeyConfig()).isNotNull();
    assertThat(GsiConfiguration.builder().toString()).hasSizeGreaterThan(0);

    assertThatThrownBy(() -> new KeyConfiguration(resourceLoader, gsiConfig).sigKey())
        .isInstanceOf(GsiException.class);
  }
}
