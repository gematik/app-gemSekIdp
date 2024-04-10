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

package de.gematik.idp.gsi.server.services;

import de.gematik.idp.data.FederationPubKey;
import de.gematik.idp.data.JwtHelper;
import de.gematik.idp.gsi.server.data.SignedJwksBody;
import java.time.ZonedDateTime;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;

@RequiredArgsConstructor
@Slf4j
public class JwksBuilder {

  @Autowired FederationPubKey esSigPubKey;
  @Autowired FederationPubKey tokenSigPubKey;

  public SignedJwksBody build(final String serverUrl) {
    final ZonedDateTime currentTime = ZonedDateTime.now();
    return SignedJwksBody.builder()
        .iat(currentTime.toEpochSecond())
        .iss(serverUrl)
        .keys(JwtHelper.getJwks(esSigPubKey, tokenSigPubKey).getKeys())
        .build();
  }
}
