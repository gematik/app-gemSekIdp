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

import de.gematik.idp.field.ClaimName;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class ClaimHelper {

  private static final Map<String, List<ClaimName>> scopesToClaimMap;

  static {
    scopesToClaimMap =
        Map.of(
            "openid",
            List.of(),
            "urn:telematik:geburtsdatum",
            List.of(ClaimName.BIRTHDATE),
            "urn:telematik:alter",
            List.of(ClaimName.TELEMATIK_ALTER),
            "urn:telematik:display_name",
            List.of(ClaimName.TELEMATIK_DISPLAY_NAME),
            "urn:telematik:given_name",
            List.of(ClaimName.TELEMATIK_GIVEN_NAME),
            "urn:telematik:geschlecht",
            List.of(ClaimName.TELEMATIK_GESCHLECHT),
            "urn:telematik:email",
            List.of(ClaimName.TELEMATIK_EMAIL),
            "urn:telematik:versicherter",
            List.of(
                ClaimName.TELEMATIK_PROFESSION,
                ClaimName.TELEMATIK_ID,
                ClaimName.TELEMATIK_ORGANIZATION),
            "urn:telematik:family_name",
            List.of(ClaimName.TELEMATIK_FAMILY_NAME));
  }

  public static Set<String> getClaimsForScopeSet(final Set<String> requestedScopes) {
    return requestedScopes.stream()
        .filter(scopesToClaimMap::containsKey)
        .flatMap(scope -> scopesToClaimMap.get(scope).stream().map(ClaimName::getJoseName))
        .collect(Collectors.toSet());
  }
}
