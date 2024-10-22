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

package de.gematik.idp.gsi.server.data;

import de.gematik.idp.gsi.server.services.EntityStatementRpReader;
import de.gematik.idp.gsi.server.services.EntityStatementRpVerifier;
import de.gematik.idp.token.JsonWebToken;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.List;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.lang.JoseException;

@Getter
@RequiredArgsConstructor
public class RpToken {

  private final JsonWebToken token;

  public boolean isExpired() {
    return !token.getExpiresAt().isBefore(ZonedDateTime.now());
  }

  public void verify(final JsonWebKeySet jwks) {
    EntityStatementRpVerifier.verifyEntityStmntRp(token, jwks);
  }

  public List<X509Certificate> getRpTlsClientCertificates() {
    return EntityStatementRpReader.getRpTlsClientCerts(token);
  }

  public PublicJsonWebKey getRpEncKey() throws JoseException {
    return EntityStatementRpReader.getRpEncKey(token);
  }

  public void verifyRedirectUriExistsInEntityStmnt(final String redirectUri) {
    EntityStatementRpVerifier.verifyRedirectUriExistsInEntityStmnt(token, redirectUri);
  }

  public void verifyRequestedScopesListedInEntityStmnt(final String scopeParameter) {
    EntityStatementRpVerifier.verifyRequestedScopesListedInEntityStmnt(token, scopeParameter);
  }
}
