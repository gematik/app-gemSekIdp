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

package de.gematik.idp.gsi.fedmaster.services;

import de.gematik.idp.data.FederationPrivKey;
import de.gematik.idp.data.FederationPubKey;
import de.gematik.idp.data.JwtHelper;
import de.gematik.idp.gsi.fedmaster.KeyConfiguration;
import de.gematik.idp.gsi.fedmaster.data.EntityStatementFederationMember;
import de.gematik.idp.gsi.fedmaster.data.IdentityProviderConfig;
import de.gematik.idp.gsi.fedmaster.data.RelyingPartyConfig;
import de.gematik.idp.gsi.fedmaster.exceptions.FedmasterException;
import jakarta.annotation.Resource;
import java.time.ZonedDateTime;
import java.util.List;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

@RequiredArgsConstructor
public class EntityStatementFederationMemberBuilder {

  private static final int ENTITY_STATEMENT_FD_TTL_DAYS = 7;
  @Resource FederationPrivKey entityStatementSigKey;
  @Resource List<RelyingPartyConfig> relyingPartyConfigs;
  @Resource List<IdentityProviderConfig> identityProviderConfigs;

  public EntityStatementFederationMember buildEntityStatementFederationMember(
      @NonNull final String serverUrl, @NonNull final String sub, final String aud) {
    final ZonedDateTime currentTime = ZonedDateTime.now();
    final EntityStatementFederationMember entityStatementFederationMember =
        EntityStatementFederationMember.builder()
            .exp(currentTime.plusDays(ENTITY_STATEMENT_FD_TTL_DAYS).toEpochSecond())
            .iat(currentTime.toEpochSecond())
            .iss(serverUrl)
            .sub(sub)
            .jwks(JwtHelper.getJwks(getKey(sub)))
            .build();
    if (aud != null) {
      entityStatementFederationMember.setAud(aud);
    }
    return entityStatementFederationMember;
  }

  private FederationPubKey getKey(final String sub) {
    for (final RelyingPartyConfig relyingPartyConfig : relyingPartyConfigs) {
      if (relyingPartyConfig.getIssuer().equals(sub)) {
        return KeyConfiguration.getFederationPubKey(relyingPartyConfig.getKeyConfig());
      }
    }
    for (final IdentityProviderConfig identityProviderConfig : identityProviderConfigs) {
      if (identityProviderConfig.getIssuer().equals(sub)) {
        return KeyConfiguration.getFederationPubKey(identityProviderConfig.getKeyConfig());
      }
    }
    throw new FedmasterException(
        "Subject [" + sub + "] is unknown", HttpStatus.BAD_REQUEST, "6011");
  }
}
