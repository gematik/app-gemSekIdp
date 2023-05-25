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

import static de.gematik.idp.data.Oauth2ErrorCode.INVALID_REQUEST;
import static de.gematik.idp.field.ClaimName.AUTHENTICATION_CLASS_REFERENCE;
import static de.gematik.idp.field.ClaimName.AUTHENTICATION_METHODS_REFERENCE;
import static de.gematik.idp.field.ClaimName.TELEMATIK_GIVEN_NAME;
import static de.gematik.idp.field.ClaimName.TELEMATIK_ID;
import static de.gematik.idp.field.ClaimName.TELEMATIK_ORGANIZATION;
import static de.gematik.idp.field.ClaimName.TELEMATIK_PROFESSION;

import de.gematik.idp.IdpConstants;
import de.gematik.idp.gsi.server.data.TiUser;
import de.gematik.idp.gsi.server.exceptions.GsiException;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthenticationService {

  private static final TiUser user12345678 =
      TiUser.builder().kvnr("12345678").givenName("Mueller").build();
  /*
  simulate user authentication
   */
  public void doAuthentication(final Map<String, Object> userData, final String userId) {

    if (userId.equals(user12345678.getKvnr())) {
      // user found in database ;-)
      userData.put(TELEMATIK_PROFESSION.getJoseName(), "TODO PROFESSION");
      userData.put(TELEMATIK_GIVEN_NAME.getJoseName(), user12345678.getGivenName());
      userData.put(TELEMATIK_ORGANIZATION.getJoseName(), "TODO ORGANIZATION_NAME");
      userData.put(TELEMATIK_ID.getJoseName(), user12345678.getKvnr());

      userData.put(AUTHENTICATION_CLASS_REFERENCE.getJoseName(), IdpConstants.EIDAS_LOA_HIGH);
      userData.put(AUTHENTICATION_METHODS_REFERENCE.getJoseName(), "TODO amr");
    } else {
      throw new GsiException(INVALID_REQUEST, "invalid userId", HttpStatus.BAD_REQUEST);
    }
  }
}
