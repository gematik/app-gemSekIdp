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

package de.gematik.idp.gsi.server.token;

import static de.gematik.idp.field.ClaimName.*;
import static de.gematik.idp.gsi.server.data.GsiConstants.IDTOKEN_TTL_MINUTES;
import static de.gematik.idp.gsi.server.data.GsiConstants.SCOPES_TO_CLAIM_MAP;

import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.authentication.JwtBuilder;
import de.gematik.idp.field.ClaimName;
import de.gematik.idp.token.JsonWebToken;
import java.time.ZonedDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import lombok.RequiredArgsConstructor;
import org.jose4j.jwt.NumericDate;

@RequiredArgsConstructor
public class IdTokenBuilder {

  private final IdpJwtProcessor jwtProcessor;
  private final String issuerUrl;
  private final Set<String> requestedScopes;
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
    claimsMap.putAll(filterUserDataClaimsWithRespectToScope(userDataClaims, requestedScopes));

    final Map<String, Object> headerClaims = new HashMap<>();
    headerClaims.put(TYPE.getJoseName(), "JWT");

    return jwtProcessor.buildJwt(
        new JwtBuilder().addAllBodyClaims(claimsMap).addAllHeaderClaims(headerClaims));
  }

  private Map<String, Object> filterUserDataClaimsWithRespectToScope(
      final Map<String, Object> userDataClaims, final Set<String> requestedScopes) {
    final Stream<String> requestedClaims =
        requestedScopes.stream().flatMap(this::getClaimsForScope);
    final Stream<String> claimsForAuthenticationDetails =
        Stream.of(
            AUTHENTICATION_CLASS_REFERENCE.getJoseName(),
            AUTHENTICATION_METHODS_REFERENCE.getJoseName());
    return Stream.concat(requestedClaims, claimsForAuthenticationDetails)
        .collect(Collectors.toMap(claim -> claim, userDataClaims::get));
  }

  private Stream<String> getClaimsForScope(final String scope) {
    return SCOPES_TO_CLAIM_MAP.get(scope).stream().map(ClaimName::getJoseName);
  }
}
