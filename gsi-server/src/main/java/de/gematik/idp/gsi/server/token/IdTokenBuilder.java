/*
 * Copyright (Date see Readme), gematik GmbH
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

package de.gematik.idp.gsi.server.token;

import static de.gematik.idp.field.ClaimName.*;
import static de.gematik.idp.gsi.server.data.GsiConstants.IDTOKEN_TTL_MINUTES;

import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.authentication.JwtBuilder;
import de.gematik.idp.token.JsonWebToken;
import java.time.ZonedDateTime;
import java.util.HashMap;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.jose4j.jwt.NumericDate;

@RequiredArgsConstructor
public class IdTokenBuilder {

  private final IdpJwtProcessor jwtProcessor;
  private final String issuerUrl;
  private final String nonceFachdienst;
  private final String fachdienstClientId;
  private final Map<String, Object> userDataClaims;

  public JsonWebToken buildIdToken() {
    final Map<String, Object> claimsMap = new HashMap<>();
    final ZonedDateTime now = ZonedDateTime.now();
    claimsMap.put(ISSUER.getJoseName(), issuerUrl);
    claimsMap.put(
        SUBJECT.getJoseName(),
        userDataClaims.get(TELEMATIK_ID.getJoseName()) + "-" + fachdienstClientId);
    claimsMap.put(ISSUED_AT.getJoseName(), now.toEpochSecond());
    claimsMap.put(
        EXPIRES_AT.getJoseName(),
        NumericDate.fromSeconds(now.plusMinutes(IDTOKEN_TTL_MINUTES).toEpochSecond()).getValue());
    claimsMap.put(AUDIENCE.getJoseName(), fachdienstClientId);
    claimsMap.put(NONCE.getJoseName(), nonceFachdienst);
    claimsMap.putAll(userDataClaims);

    final Map<String, Object> headerClaims = new HashMap<>();
    headerClaims.put(TYPE.getJoseName(), "JWT");

    return jwtProcessor.buildJwt(
        new JwtBuilder()
            .addAllBodyClaims(claimsMap)
            .addAllHeaderClaims(headerClaims)
            .includeSignerCertificateInHeader(true));
  }
}
