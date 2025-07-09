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

package de.gematik.idp.gsi.server.util;

import static de.gematik.idp.gsi.server.util.ClaimHelper.getClaimsForScopeSet;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

import de.gematik.idp.field.ClaimName;
import java.util.Arrays;
import java.util.HashSet;
import org.junit.jupiter.api.Test;

class ClaimHelperTest {

  @Test
  void test_getClaimsForValidScopeSet_VALID() {
    assertThat(
            getClaimsForScopeSet(
                new HashSet<>(
                    Arrays.asList(
                        "openid",
                        "urn:telematik:family_name",
                        "urn:telematik:versicherter",
                        "urn:telematik:display_name"))))
        .containsExactlyInAnyOrder(
            ClaimName.TELEMATIK_FAMILY_NAME.getJoseName(),
            ClaimName.TELEMATIK_PROFESSION.getJoseName(),
            ClaimName.TELEMATIK_ID.getJoseName(),
            ClaimName.TELEMATIK_ORGANIZATION.getJoseName(),
            ClaimName.TELEMATIK_DISPLAY_NAME.getJoseName());
  }

  @Test
  void test_getClaimsForInvalidScopeSet_INVALID() {
    assertDoesNotThrow(
        () -> getClaimsForScopeSet(new HashSet<>(Arrays.asList("openid", "invalid:scope"))));
  }
}
