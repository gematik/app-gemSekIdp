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

import de.gematik.idp.gsi.server.data.RpToken;
import de.gematik.idp.token.JsonWebToken;
import de.gematik.idp.token.TokenClaimExtraction;
import java.util.HashMap;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jose4j.jwk.JsonWebKeySet;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@ConditionalOnProperty(
    prefix = "gsi",
    name = "fedmasterMode",
    havingValue = "remote",
    matchIfMissing = true)
@RequiredArgsConstructor
public class TokenRepositoryRpRemote implements TokenRepositoryRp {

  private final Map<String, RpToken> entityStmtsOfRp = new HashMap<>();
  private final TokenRepositoryFedmaster tokenRepositoryFedmaster;

  @Override
  public RpToken getEntityStatementRp(final String issuerRp) {
    log.debug("Entitystatement of RP [{}] requested.", issuerRp);
    updateStatementRpIfExpiredAndNewIsAvailable(issuerRp);
    log.debug(
        "Entitystatement of RP [{}] stored. JWT: {}",
        issuerRp,
        entityStmtsOfRp.get(issuerRp).token().getRawString());
    return entityStmtsOfRp.get(issuerRp);
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

  private void fetchAndStoreEntityStmnt(final String issuer) {
    final RpToken entityStmnt = HttpClient.fetchEntityStatementRp(issuer);

    final JsonWebToken esAboutRp = tokenRepositoryFedmaster.getEntityStatementAboutRp(issuer);
    final JsonWebKeySet jwks = TokenClaimExtraction.extractJwksFromBody(esAboutRp.getRawString());
    entityStmnt.verify(jwks);

    entityStmtsOfRp.put(issuer, entityStmnt);
    log.debug(
        "Entitystatement of RP [{}] stored. JWT: {}",
        issuer,
        entityStmtsOfRp.get(issuer).token().getRawString());
  }
}
