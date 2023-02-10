package de.gematik.idp.gsi.server;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import de.gematik.idp.gsi.server.configuration.GsiConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class GsiServerTests {
  @Autowired private GsiConfiguration gsiConfiguration;

  @Test
  void contextLoads() {
    assertThat(gsiConfiguration).isNotNull();
  }
}
