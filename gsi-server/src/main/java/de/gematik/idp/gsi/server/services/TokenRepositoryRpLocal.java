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
import java.util.HashMap;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@ConditionalOnProperty(prefix = "gsi", name = "fedmasterMode", havingValue = "local")
public class TokenRepositoryRpLocal implements TokenRepositoryRp {

  private final Map<String, RpToken> entityStmtsOfRp = new HashMap<>();

  @Override
  public RpToken getEntityStatementRp(final String issuerRp) {
    log.debug("Entitystatement of RP [{}] requested in local mode.", issuerRp);
    if (entityStmtsOfRp.containsKey(issuerRp)) {
      return entityStmtsOfRp.get(issuerRp);
    }

    final RpToken entityStmnt = HttpClient.fetchEntityStatementRp(issuerRp);
    entityStmtsOfRp.put(issuerRp, entityStmnt);
    log.debug(
        "Entitystatement of RP [{}] stored in local mode without Fedmaster validation.", issuerRp);
    return entityStmnt;
  }
}
