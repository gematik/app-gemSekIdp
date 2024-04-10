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

package de.gematik.idp.gsi.server.services;

import static de.gematik.idp.field.ClaimName.AUTHENTICATION_CLASS_REFERENCE;
import static de.gematik.idp.field.ClaimName.AUTHENTICATION_METHODS_REFERENCE;
import static de.gematik.idp.field.ClaimName.TELEMATIK_GIVEN_NAME;
import static de.gematik.idp.field.ClaimName.TELEMATIK_ID;
import static de.gematik.idp.field.ClaimName.TELEMATIK_PROFESSION;
import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.idp.gsi.server.data.InsuredPersonsService;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

@Slf4j
class AuthenticationServiceTest {

  @BeforeEach
  void init() {}

  @Test
  void authenticationTest_LegacyUser12345678() {
    final AuthenticationService authenticationService =
        new AuthenticationService(new InsuredPersonsService("versicherte.gesundheitsid.json"));
    final Map<String, Object> userData = new HashMap<>();
    final Set<String> selectedClaimsSet =
        Set.of(
            TELEMATIK_ID.getJoseName(),
            AUTHENTICATION_CLASS_REFERENCE.getJoseName(),
            AUTHENTICATION_METHODS_REFERENCE.getJoseName(),
            TELEMATIK_PROFESSION.getJoseName(),
            TELEMATIK_GIVEN_NAME.getJoseName());
    authenticationService.doAuthentication(userData, "12345678", selectedClaimsSet);
    assertThat(userData.keySet())
        .containsExactlyInAnyOrder(
            TELEMATIK_PROFESSION.getJoseName(),
            TELEMATIK_GIVEN_NAME.getJoseName(),
            TELEMATIK_ID.getJoseName(),
            AUTHENTICATION_CLASS_REFERENCE.getJoseName(),
            AUTHENTICATION_METHODS_REFERENCE.getJoseName());
    assertThat(userData).containsEntry(TELEMATIK_ID.getJoseName(), "X110411675");
  }
}
