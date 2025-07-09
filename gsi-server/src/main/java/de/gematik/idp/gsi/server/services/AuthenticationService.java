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

import de.gematik.idp.gsi.server.data.InsuredPersonsService;
import java.util.List;
import java.util.Map;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthenticationService {
  private final InsuredPersonsService insuredPersonsService;

  /*
  simulate user authentication
   */
  public void doAuthentication(
      final Map<String, Object> userData,
      final String userId,
      final Set<String> selectedClaimsSet) {
    final Map<String, Object> user = insuredPersonsService.getPerson(userId);

    selectedClaimsSet.forEach(claim -> userData.put(claim, user.get(claim)));
    userData.put(
        AUTHENTICATION_CLASS_REFERENCE.getJoseName(),
        user.containsKey(AUTHENTICATION_CLASS_REFERENCE.getJoseName())
            ? user.get(AUTHENTICATION_CLASS_REFERENCE.getJoseName())
            : "gematik-ehealth-loa-high");
    userData.put(
        AUTHENTICATION_METHODS_REFERENCE.getJoseName(),
        user.containsKey(AUTHENTICATION_METHODS_REFERENCE.getJoseName())
            ? ((List<String>) user.get(AUTHENTICATION_METHODS_REFERENCE.getJoseName()))
                .toArray(String[]::new)
            : new String[] {"urn:telematik:auth:eGK"});
  }
}
