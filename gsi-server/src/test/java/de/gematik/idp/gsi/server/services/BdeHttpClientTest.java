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

package de.gematik.idp.gsi.server.services;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import java.util.ArrayDeque;
import java.util.List;
import kong.unirest.core.Config;
import kong.unirest.core.Unirest;
import kong.unirest.core.UnirestInstance;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

class BdeHttpClientTest {

  @RegisterExtension
  static WireMockExtension server =
      WireMockExtension.newInstance().options(wireMockConfig().dynamicPort()).build();

  private final ApplicationContextRunner contextRunner =
      new ApplicationContextRunner().withUserConfiguration(BdeHttpClient.class);

  @Test
  void sendsRepeatedlyAfterGlobalClientHasBeenBuiltWithoutChangingItsConfiguration() {
    server.stubFor(get(urlEqualTo("/federation")).willReturn(aResponse().withBody("federation")));
    server.stubFor(post(urlEqualTo("/bde")).willReturn(aResponse().withBody("ok")));
    Unirest.config().reset();
    try {
      assertThat(Unirest.get(server.baseUrl() + "/federation").asString().getBody())
          .isEqualTo("federation");
      assertThat(Unirest.config().isRunning()).isTrue();

      try (final BdeHttpClient client = new BdeHttpClient()) {
        final ArrayDeque<String> logs = new ArrayDeque<>(List.of("first", "second"));
        client.sendLogsToBde(logs, "test_perf.log", server.baseUrl() + "/bde");
        client.sendLogsToBde(logs, "test_perf.log", server.baseUrl() + "/bde");
      }

      server.verify(
          2,
          postRequestedFor(urlEqualTo("/bde"))
              .withHeader("Content-Type", equalTo("application/octet-stream"))
              .withHeader("Accept-Encoding", equalTo("gzip, deflate"))
              .withHeader("filename", equalTo("test_perf.log"))
              .withRequestBody(equalTo("first\nsecond")));
      assertThat(Unirest.config().isVerifySsl()).isTrue();
      assertThat(Unirest.config().isRunning()).isTrue();
      assertThat(Unirest.get(server.baseUrl() + "/federation").asString().getBody())
          .isEqualTo("federation");
    } finally {
      Unirest.config().reset();
    }
  }

  @Test
  void sendsPlaceholderForEmptyLogs() {
    server.stubFor(post(urlEqualTo("/bde")).willReturn(aResponse().withBody("ok")));
    try (final BdeHttpClient client = new BdeHttpClient()) {
      client.sendLogsToBde(new ArrayDeque<>(), "empty_perf.log", server.baseUrl() + "/bde");
    }
    server.verify(postRequestedFor(urlEqualTo("/bde")).withRequestBody(equalTo("leer")));
  }

  @Test
  void configuresOnceAndClosesDedicatedInstanceWhenSpringContextCloses() {
    final UnirestInstance instance = mock(UnirestInstance.class);
    final Config config = mock(Config.class);
    when(instance.config()).thenReturn(config);
    try (final var unirest = mockStatic(Unirest.class)) {
      unirest.when(Unirest::spawnInstance).thenReturn(instance);

      contextRunner
          .withPropertyValues("gsi.bdeLoggingEnabled=true")
          .run(
              context -> {
                assertThat(context).hasSingleBean(BdeHttpClient.class);
                assertThat(context.getBean(BdeHttpClient.class))
                    .isSameAs(context.getBean(BdeHttpClient.class));
                verify(config).verifySsl(false);
                verify(instance, never()).close();
                unirest.verify(Unirest::spawnInstance);
              });

      verify(instance).close();
    }
  }

  @Test
  void doesNotCreateClientWhenBdeLoggingIsDisabledOrUnspecified() {
    try (final var unirest = mockStatic(Unirest.class)) {
      contextRunner.run(context -> assertThat(context).doesNotHaveBean(BdeHttpClient.class));
      contextRunner
          .withPropertyValues("gsi.bdeLoggingEnabled=false")
          .run(context -> assertThat(context).doesNotHaveBean(BdeHttpClient.class));
      unirest.verifyNoInteractions();
    }
  }
}
