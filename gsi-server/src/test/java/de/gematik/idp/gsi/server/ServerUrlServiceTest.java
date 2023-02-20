package de.gematik.idp.gsi.server;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

@SpringBootTest(
    classes = GsiServer.class,
    webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT)
class ServerUrlServiceTest {

  @Autowired ServerUrlService serverUrlService;
  @LocalServerPort private int localServerPort;

  @Test
  void testDetermineServerUrl() {
    assertThat(serverUrlService.determineServerUrl()).contains(String.valueOf(localServerPort));
  }

  @Test
  void getServerPort() {
    assertThat(serverUrlService.getServerPort()).isEqualTo(localServerPort);
  }
}
