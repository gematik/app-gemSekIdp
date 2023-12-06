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
import static de.gematik.idp.field.ClaimName.BIRTHDATE;
import static de.gematik.idp.field.ClaimName.TELEMATIK_ALTER;
import static de.gematik.idp.field.ClaimName.TELEMATIK_DISPLAY_NAME;
import static de.gematik.idp.field.ClaimName.TELEMATIK_EMAIL;
import static de.gematik.idp.field.ClaimName.TELEMATIK_GESCHLECHT;
import static de.gematik.idp.field.ClaimName.TELEMATIK_GIVEN_NAME;
import static de.gematik.idp.field.ClaimName.TELEMATIK_ID;
import static de.gematik.idp.field.ClaimName.TELEMATIK_ORGANIZATION;
import static de.gematik.idp.field.ClaimName.TELEMATIK_PROFESSION;

import de.gematik.idp.IdpConstants;
import de.gematik.idp.gsi.server.data.InsuredPersonsService;
import java.util.Map;
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
  public void doAuthentication(final Map<String, Object> userData, final String userId) {
    final Map<String, String> user = insuredPersonsService.getPerson(userId);

    userData.put(TELEMATIK_PROFESSION.getJoseName(), user.get(TELEMATIK_PROFESSION.getJoseName()));
    userData.put(TELEMATIK_GIVEN_NAME.getJoseName(), user.get(TELEMATIK_GIVEN_NAME.getJoseName()));
    userData.put(
        TELEMATIK_ORGANIZATION.getJoseName(), user.get(TELEMATIK_ORGANIZATION.getJoseName()));
    userData.put(TELEMATIK_ID.getJoseName(), user.get(TELEMATIK_ID.getJoseName()));
    userData.put(AUTHENTICATION_CLASS_REFERENCE.getJoseName(), IdpConstants.EIDAS_LOA_HIGH);
    userData.put(AUTHENTICATION_METHODS_REFERENCE.getJoseName(), "TODO amr");
    userData.put(TELEMATIK_ALTER.getJoseName(), user.get(TELEMATIK_ALTER.getJoseName()));
    userData.put(
        TELEMATIK_DISPLAY_NAME.getJoseName(), user.get(TELEMATIK_DISPLAY_NAME.getJoseName()));
    userData.put(TELEMATIK_EMAIL.getJoseName(), user.get(TELEMATIK_EMAIL.getJoseName()));
    userData.put(TELEMATIK_GESCHLECHT.getJoseName(), user.get(TELEMATIK_GESCHLECHT.getJoseName()));
    userData.put(BIRTHDATE.getJoseName(), user.get(BIRTHDATE.getJoseName()));
  }
}
