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

import static de.gematik.idp.field.ClaimName.AUTHENTICATION_CLASS_REFERENCE;
import static de.gematik.idp.field.ClaimName.AUTHENTICATION_METHODS_REFERENCE;
import static de.gematik.idp.field.ClaimName.TELEMATIK_GIVEN_NAME;
import static de.gematik.idp.field.ClaimName.TELEMATIK_ID;
import static de.gematik.idp.field.ClaimName.TELEMATIK_PROFESSION;
import static de.gematik.idp.gsi.server.data.GsiConstants.FALLBACK_KVNR;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import de.gematik.idp.gsi.server.data.InsuredPersonsService;
import de.gematik.idp.gsi.server.exceptions.GsiException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

@Slf4j
class AuthenticationServiceTest {
  private final AuthenticationService authenticationService =
      new AuthenticationService(new InsuredPersonsService("versicherte.gesundheitsid.json"));

  @BeforeEach
  void init() {}

  @Test
  void test_authentication_unknownUser() {
    final Map<String, Object> userData = new HashMap<>();
    final Set<String> selectedClaimsSet = getSelectedClaimSet();
    assertThatThrownBy(
            () -> authenticationService.doAuthentication(userData, "12345678", selectedClaimsSet))
        .isInstanceOf(GsiException.class);
  }

  @Test
  void test_authentication_LegacyUser() {
    final Map<String, Object> userData = new HashMap<>();
    final Set<String> selectedClaimsSet = getSelectedClaimSet();
    authenticationService.doAuthentication(userData, FALLBACK_KVNR, selectedClaimsSet);
    assertThat(userData.keySet()).isEqualTo(selectedClaimsSet);
    assertThat(userData).containsEntry(TELEMATIK_ID.getJoseName(), FALLBACK_KVNR);
  }

  @Test
  void test_authentication_User_AcrAndAmrNotSet() {
    final Map<String, Object> userData = new HashMap<>();
    final Set<String> selectedClaimsSet = getSelectedClaimSet();
    authenticationService.doAuthentication(userData, "G049950590", selectedClaimsSet);
    assertThat(userData.keySet()).isEqualTo(selectedClaimsSet);
    assertThat(userData).containsEntry(TELEMATIK_ID.getJoseName(), "G049950590");
  }

  private static Set<String> getSelectedClaimSet() {
    return Set.of(
        TELEMATIK_ID.getJoseName(),
        AUTHENTICATION_CLASS_REFERENCE.getJoseName(),
        AUTHENTICATION_METHODS_REFERENCE.getJoseName(),
        TELEMATIK_PROFESSION.getJoseName(),
        TELEMATIK_GIVEN_NAME.getJoseName());
  }
}
