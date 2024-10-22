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

import static de.gematik.idp.data.Oauth2ErrorCode.INVALID_REQUEST;

import de.gematik.idp.IdpConstants;
import de.gematik.idp.gsi.server.data.RpToken;
import de.gematik.idp.gsi.server.exceptions.GsiException;
import de.gematik.idp.token.JsonWebToken;
import java.util.Optional;
import kong.unirest.core.HttpResponse;
import kong.unirest.core.Unirest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;

@Slf4j
public abstract class HttpClient {

  public static Optional<JsonWebToken> fetchSignedJwks(final String signedJwksUri) {
    final HttpResponse<String> resp = Unirest.get(signedJwksUri).asString();
    if (resp.isSuccess()) {
      // TODO check signature
      return Optional.of(new JsonWebToken(resp.getBody()));
    }
    return Optional.empty();
  }

  public static RpToken fetchEntityStatementRp(final String issuer) {
    final HttpResponse<String> resp =
        Unirest.get(issuer + IdpConstants.ENTITY_STATEMENT_ENDPOINT).asString();
    if (resp.getStatus() == HttpStatus.OK.value()) {
      return new RpToken(new JsonWebToken(resp.getBody()));
    } else {
      log.info(resp.getBody());
      throw new GsiException(
          INVALID_REQUEST,
          "No entity statement of relying party ["
              + issuer
              + "] available. Reason: "
              + resp.getBody()
              + HttpStatus.valueOf(resp.getStatus()),
          HttpStatus.BAD_REQUEST);
    }
  }

  public static JsonWebToken fetchEntityStatementAboutRp(
      final String sub, final String fedmasterUrl, final String entityStmntEndpoint) {
    log.info("FedmasterUrl: " + fedmasterUrl);
    final HttpResponse<String> resp =
        Unirest.get(entityStmntEndpoint)
            .queryString("iss", fedmasterUrl)
            .queryString("sub", sub)
            .asString();
    if (resp.getStatus() == HttpStatus.OK.value()) {
      return new JsonWebToken(resp.getBody());
    } else {
      log.info(resp.getBody());
      throw new GsiException(
          INVALID_REQUEST,
          "No entity statement about relying party ["
              + sub
              + "] at Fedmaster iss: "
              + fedmasterUrl
              + " available. Reason: "
              + resp.getBody()
              + HttpStatus.valueOf(resp.getStatus()),
          HttpStatus.BAD_REQUEST);
    }
  }
}
