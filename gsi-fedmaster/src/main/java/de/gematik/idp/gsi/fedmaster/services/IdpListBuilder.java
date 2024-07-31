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

import static de.gematik.idp.gsi.fedmaster.Constants.LOGO_URI;

import de.gematik.idp.gsi.fedmaster.data.IdentityProviderConfig;
import de.gematik.idp.gsi.fedmaster.data.IdpList;
import de.gematik.idp.gsi.fedmaster.data.IdpListEntry;
import jakarta.annotation.Resource;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.List;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class IdpListBuilder {

  private static final int ENTITY_STATEMENT_TTL_DAYS = 1;
  @Resource List<IdentityProviderConfig> identityProviderConfigs;

  public IdpList buildIdpList(final String serverUrl) {
    final ZonedDateTime currentTime = ZonedDateTime.now();
    return IdpList.builder()
        .exp(currentTime.plusDays(ENTITY_STATEMENT_TTL_DAYS).toEpochSecond())
        .iat(currentTime.toEpochSecond())
        .iss(serverUrl)
        .idpEntity(createIdpEntityList())
        .build();
  }

  private List<IdpListEntry> createIdpEntityList() {
    final List<IdpListEntry> entityList = new ArrayList<>();

    for (final IdentityProviderConfig identityProviderConfig : identityProviderConfigs) {
      entityList.add(
          IdpListEntry.builder()
              .iss(identityProviderConfig.getIssuer())
              .organizationName(identityProviderConfig.getOrganizationName())
              .logoUri(LOGO_URI)
              .userTypeSupported("IP")
              .build());
    }

    return entityList;
  }
}
