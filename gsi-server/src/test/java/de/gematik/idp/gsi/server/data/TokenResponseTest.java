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

package de.gematik.idp.gsi.server.data;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import org.junit.jupiter.api.Test;

class TokenResponseTest {

  public static final int EXPIRES_IN = 300;

  @Test
  void testBuild() {
    final TokenResponse tokenResponse =
        TokenResponse.builder()
            .idToken("ID_TOKEN")
            .accessToken("ACCESS_TOKEN")
            .tokenType("Bearer")
            .expiresIn(EXPIRES_IN)
            .build();
    assertThat(tokenResponse).isNotNull();
    assertThat(tokenResponse.getIdToken()).isEqualTo("ID_TOKEN");
    assertThat(tokenResponse.getExpiresIn()).isEqualTo(EXPIRES_IN);
    assertThat(tokenResponse.getIdToken()).isEqualTo("ID_TOKEN");
    assertThat(tokenResponse.getTokenType()).isEqualTo("Bearer");

    assertThat(TokenResponse.builder().toString()).hasSizeGreaterThan(0);
  }
}
