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

import static de.gematik.idp.IdpConstants.IDP_LIST_ENDPOINT;
import static de.gematik.idp.gsi.fedmaster.Constants.FEDMASTER_FEDERATION_FETCH_ENDPOINT;
import static de.gematik.idp.gsi.fedmaster.Constants.FED_LIST_ENDPOINT;

import de.gematik.idp.data.FederationPubKey;
import de.gematik.idp.data.JwtHelper;
import de.gematik.idp.gsi.fedmaster.data.EntityStatement;
import de.gematik.idp.gsi.fedmaster.data.FederationEntity;
import de.gematik.idp.gsi.fedmaster.data.Metadata;
import jakarta.annotation.Resource;
import java.time.ZonedDateTime;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class EntityStatementBuilder {

  private static final int ENTITY_STATEMENT_TTL_DAYS = 7;
  @Resource FederationPubKey esSigPubKey;

  public EntityStatement buildEntityStatement(final String serverUrl) {
    final ZonedDateTime currentTime = ZonedDateTime.now();
    return EntityStatement.builder()
        .exp(currentTime.plusDays(ENTITY_STATEMENT_TTL_DAYS).toEpochSecond())
        .iat(currentTime.toEpochSecond())
        .iss(serverUrl)
        .sub(serverUrl)
        .jwks(JwtHelper.getJwks(esSigPubKey))
        .metadata(getMetadata(serverUrl))
        .build();
  }

  private Metadata getMetadata(final String serverUrl) {
    final FederationEntity federationEntity =
        FederationEntity.builder()
            .federationFetchEndpoint(serverUrl + FEDMASTER_FEDERATION_FETCH_ENDPOINT)
            .federationListEndpoint(serverUrl + FED_LIST_ENDPOINT)
            .idpListEndpoint(serverUrl + IDP_LIST_ENDPOINT)
            .build();
    return Metadata.builder().federationEntity(federationEntity).build();
  }
}
