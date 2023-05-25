/*
 *  Copyright [2023] gematik GmbH
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

package de.gematik.idp.gsi.server.data;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import lombok.Builder;
import lombok.Getter;

/** Federation Authorization session */
@Getter
@Builder
public class FedIdpAuthSession {

  // outer session related artifacts taken from fachdienst request
  private final String fachdienstClientId;
  private final String fachdienstState;
  private final String fachdienstCodeChallenge;
  private final String fachdienstCodeChallengeMethod;
  private final String fachdienstNonce;
  private final Set<String> requestedScopes;
  // will be sent in message nr.7
  private final String fachdienstRedirectUri;
  private final String authorizationCode;

  // contains data taken from messages nr.6a ... nr.6b
  private final Map<String, Object> userData = new HashMap<>();

  // IDP-Sektoral, inner session related artifacts
  private final String requestUri;
  private final String expiresAt;

  @Override
  public String toString() {
    return "fachdienstClientId: "
        + fachdienstClientId
        + "\n fachdienstCodeChallenge: "
        + fachdienstCodeChallenge
        + "\n fachdienstCodeChallengeMethod: "
        + fachdienstCodeChallengeMethod
        + "\n fachdienstNonce: "
        + fachdienstNonce
        + "\n requestedScopes: "
        + requestedScopes
        + "\n fachdienstRedirectUri: "
        + fachdienstRedirectUri
        + "\n authorizationCode: "
        + authorizationCode
        + "\n requestUri: "
        + requestUri
        + "\n expiresAt: "
        + expiresAt
        + "\n userData: "
        + userData.keySet().stream()
            .map(k -> k + userData.get(k))
            .collect(Collectors.joining(", ", "{", "}"));
  }
}
