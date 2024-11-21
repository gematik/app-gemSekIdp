/*
 *  Copyright 2023 gematik GmbH
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

package de.gematik.idp.gsi.server.data;

import static de.gematik.idp.gsi.server.common.Constants.ENTITY_STMNT_IDP_FACHDIENST_EXPIRED;
import static de.gematik.idp.gsi.server.common.Constants.ENTITY_STMNT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2043;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.junit.jupiter.api.Assertions.*;

import de.gematik.idp.token.JsonWebToken;
import org.junit.jupiter.api.Test;

class RpTokenTest {

  @Test
  void test_isExpired_INVALID() {
    final RpToken invalidToken = new RpToken(new JsonWebToken(ENTITY_STMNT_IDP_FACHDIENST_EXPIRED));
    assertThat(invalidToken.isExpired()).isTrue();
  }

  @Test
  void test_isExpired_VALID() {
    final RpToken validToken =
        new RpToken(new JsonWebToken(ENTITY_STMNT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2043));
    assertThat(validToken.isExpired()).isFalse();
  }
}
