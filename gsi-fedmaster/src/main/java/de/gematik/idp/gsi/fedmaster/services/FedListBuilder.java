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

import de.gematik.idp.gsi.fedmaster.data.IdentityProviderConfig;
import de.gematik.idp.gsi.fedmaster.data.RelyingPartyConfig;
import jakarta.annotation.Resource;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.jose4j.json.internal.json_simple.JSONArray;

@RequiredArgsConstructor
public class FedListBuilder {

  @Resource private List<RelyingPartyConfig> relyingPartyConfigs;
  @Resource private List<IdentityProviderConfig> identityProviderConfigs;

  public JSONArray buildFedList() {
    final JSONArray fedList = new JSONArray();
    for (final RelyingPartyConfig relyingPartyConfig : relyingPartyConfigs) {
      fedList.add(relyingPartyConfig.getIssuer());
    }
    for (final IdentityProviderConfig identityProviderConfig : identityProviderConfigs) {
      fedList.add(identityProviderConfig.getIssuer());
    }

    return fedList;
  }
}
