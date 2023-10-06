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

import de.gematik.idp.IdpConstants;
import de.gematik.idp.gsi.server.configuration.GsiConfiguration;
import de.gematik.idp.token.JsonWebToken;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import kong.unirest.HttpResponse;
import kong.unirest.Unirest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class ServerUrlService {

  private final GsiConfiguration gsiConfiguration;
  private String fedmasterUrl;
  private String fedmasterFetchEntityStatementEndpoint;

  public String determineServerUrl() {
    return getServerUrlFromConfig()
        .orElse("Parameter \"fd-auth-server.serverUrl\" not found in configuration.");
  }

  private Optional<String> getServerUrlFromConfig() {
    return Optional.ofNullable(gsiConfiguration.getServerUrl()).filter(StringUtils::isNotBlank);
  }

  public String determineFedmasterUrl() {
    if (fedmasterUrl == null) {
      fedmasterUrl =
          Optional.ofNullable(gsiConfiguration.getFedmasterUrl())
              .filter(StringUtils::isNotBlank)
              .orElse("Parameter \"gsi.fedmasterUrl\" not found in configuration.");
    }
    return fedmasterUrl;
  }

  public String determineFetchEntityStatementEndpoint() {
    if (fedmasterFetchEntityStatementEndpoint == null) {
      final HttpResponse<String> resp =
          Unirest.get(determineFedmasterUrl() + IdpConstants.ENTITY_STATEMENT_ENDPOINT).asString();
      if (resp.getStatus() == HttpStatus.OK.value()) {
        final JsonWebToken fedmasterEntityStatement = new JsonWebToken(resp.getBody());
        fedmasterFetchEntityStatementEndpoint =
            readFederationFetchEndpointFromEntityStatement(fedmasterEntityStatement);
      } else {
        log.error(
            "Error while Fetching the Fedmasters EntityStatement: "
                + determineFedmasterUrl()
                + IdpConstants.ENTITY_STATEMENT_ENDPOINT);
      }
    }
    return fedmasterFetchEntityStatementEndpoint;
  }

  private static String readFederationFetchEndpointFromEntityStatement(
      final JsonWebToken fedmasterEntityStatement) {

    final Map<String, Object> metadata =
        Objects.requireNonNull(
            (Map<String, Object>) fedmasterEntityStatement.extractBodyClaims().get("metadata"),
            "missing claim: metadata");
    final Map<String, Object> federationEntity =
        Objects.requireNonNull(
            (Map<String, Object>) metadata.get("federation_entity"),
            "missing claim: federation_entity");
    return Objects.requireNonNull((String) federationEntity.get("federation_fetch_endpoint"));
  }

  public Optional<String> determineSignedJwksUri(final JsonWebToken entityStmntRp) {
    final Map<String, Object> bodyClaims = entityStmntRp.getBodyClaims();
    final Map<String, Object> metadata =
        Objects.requireNonNull(
            (Map<String, Object>) bodyClaims.get("metadata"), "missing claim: metadata");
    final Map<String, Object> openidRelyingParty =
        Objects.requireNonNull(
            (Map<String, Object>) metadata.get("openid_relying_party"),
            "missing claim: openid_relying_party");
    return Optional.of((String) openidRelyingParty.get("signed_jwks_uri"));
  }
}
