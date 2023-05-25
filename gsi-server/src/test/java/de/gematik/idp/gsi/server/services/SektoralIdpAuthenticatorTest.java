/*
 *  Copyright [2023] gematik GmbH
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

package de.gematik.idp.gsi.server.services;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;

import java.net.URISyntaxException;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class SektoralIdpAuthenticatorTest {

  @Autowired SektoralIdpAuthenticator sektoralIdpAuthenticator;

  @Test
  void testCreateLocationForAuthorizationResponse() {
    final AtomicReference<String> location = new AtomicReference<>();

    Assertions.assertDoesNotThrow(
        () ->
            location.set(
                sektoralIdpAuthenticator.createLocationForAuthorizationResponse(
                    "uri1", "state1", "code1")));
    assertThat(location.get()).hasSizeGreaterThan(0);
  }

  @Test
  void testCreateLocationForAuthorizationResponseUriSyntaxException() {
    final AtomicReference<String> location = new AtomicReference<>();

    assertThatThrownBy(
            () ->
                location.set(
                    sektoralIdpAuthenticator.createLocationForAuthorizationResponse(
                        "%wrongUri", "state1", "code1")))
        .hasCauseInstanceOf(URISyntaxException.class);
  }
}
