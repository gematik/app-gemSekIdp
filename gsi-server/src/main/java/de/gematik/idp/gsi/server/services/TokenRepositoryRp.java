/*
 *  Copyright 2024 gematik GmbH
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

import de.gematik.idp.gsi.server.data.RpToken;
import de.gematik.idp.token.JsonWebToken;
import de.gematik.idp.token.TokenClaimExtraction;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jose4j.jwk.JsonWebKeySet;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenRepositoryRp {

  private final Map<String, RpToken> entityStmtsOfRp = new HashMap<>();
  private final Map<String, JsonWebToken> entityStmtsAboutRp = new HashMap<>();
  private final ServerUrlService serverUrlService;
  private final PublicKey fedmasterSigKey;

  public RpToken getEntityStatementRp(final String issuerRp) {
    log.debug("Entitystatement of RP [{}] requested.", issuerRp);
    updateStatementRpIfExpiredAndNewIsAvailable(issuerRp);
    log.debug(
        "Entitystatement of RP [{}] stored. JWT: {}",
        issuerRp,
        entityStmtsOfRp.get(issuerRp).getToken().getRawString());
    return entityStmtsOfRp.get(issuerRp);
  }

  public JsonWebToken getEntityStatementAboutRp(final String sub) {
    updateStatementAboutRpIfExpiredAndNewIsAvailable(sub);
    return entityStmtsAboutRp.get(sub);
  }

  private void updateStatementRpIfExpiredAndNewIsAvailable(final String issuer) {
    if (entityStmtsOfRp.containsKey(issuer)) {
      if (entityStmtsOfRp.get(issuer).isExpired()) {
        log.debug("Entitystatement of RP [{}] is in storage but expired. Fetching...", issuer);
        fetchAndStoreEntityStmnt(issuer);
      } else {
        log.debug("Entitystatement of RP [{}] is in storage and not expired.", issuer);
      }
      return;
    }
    log.debug("Entitystatement of RP [{}] not found in storage. Fetching...", issuer);
    fetchAndStoreEntityStmnt(issuer);
  }

  private void updateStatementAboutRpIfExpiredAndNewIsAvailable(final String sub) {
    if (entityStmtsAboutRp.containsKey(sub)) {
      if (entityStmtsAboutRp.get(sub).isExpired()) {
        log.debug("Entitystatement about RP [{}] is in storage but expired. Fetching...", sub);
        fetchAndStoreEntityStmntAboutRp(sub);
      } else {
        log.debug("Entitystatement about RP [{}] is in storage and not expired.", sub);
      }
      return;
    }
    log.debug("Entitystatement about RP [{}] not found in storage. Fetching...", sub);
    fetchAndStoreEntityStmntAboutRp(sub);
  }

  private void fetchAndStoreEntityStmnt(final String issuer) {
    final RpToken entityStmnt = HttpClient.fetchEntityStatementRp(issuer);

    final JsonWebToken esAboutRp = getEntityStatementAboutRp(issuer);
    final JsonWebKeySet jwks = TokenClaimExtraction.extractJwksFromBody(esAboutRp.getRawString());
    entityStmnt.verify(jwks);

    entityStmtsOfRp.put(issuer, entityStmnt);
    log.debug(
        "Entitystatement of RP [{}] stored. JWT: {}",
        issuer,
        entityStmtsOfRp.get(issuer).getToken().getRawString());
  }

  private void fetchAndStoreEntityStmntAboutRp(final String sub) {
    final JsonWebToken entityStmntAboutRp =
        HttpClient.fetchEntityStatementAboutRp(
            sub,
            serverUrlService.determineFedmasterUrl(),
            serverUrlService.determineFetchEntityStatementEndpoint());

    entityStmntAboutRp.verify(fedmasterSigKey);
    entityStmtsAboutRp.put(sub, entityStmntAboutRp);
    log.debug(
        "Entitystatement about RP [{}] stored. JWT: {}",
        sub,
        entityStmtsAboutRp.get(sub).getRawString());
  }
}
