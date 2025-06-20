/*
 * Copyright (Date see Readme), gematik GmbH
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

import static de.gematik.idp.data.Oauth2ErrorCode.INVALID_REQUEST;
import static de.gematik.idp.data.Oauth2ErrorCode.INVALID_SCOPE;

import de.gematik.idp.exceptions.IdpJwtSignatureInvalidException;
import de.gematik.idp.gsi.server.exceptions.GsiException;
import de.gematik.idp.token.JsonWebToken;
import de.gematik.idp.token.TokenClaimExtraction;
import java.util.Arrays;
import java.util.List;
import org.jose4j.jwk.JsonWebKeySet;
import org.springframework.http.HttpStatus;

public abstract class EntityStatementRpVerifier {

  public static void verifyEntityStmntRp(final JsonWebToken entityStmnt, final JsonWebKeySet jwks) {
    final String keyIdSigEntStmnt = (String) entityStmnt.getHeaderClaims().get("kid");
    try {
      entityStmnt.verify(TokenClaimExtraction.getECPublicKey(jwks, keyIdSigEntStmnt));
    } catch (final IdpJwtSignatureInvalidException e) {
      throw new GsiException(
          INVALID_REQUEST,
          "The JWT signature of the entity statement of the relying party was invalid.",
          HttpStatus.BAD_REQUEST);
    }
  }

  public static void verifyRedirectUriExistsInEntityStmnt(
      final JsonWebToken entityStmntRp, final String redirectUri) {
    if (EntityStatementRpReader.getRedirectUrisEntityStatementRp(entityStmntRp).stream()
        .noneMatch(entry -> entry.equals(redirectUri))) {
      throw new GsiException(
          INVALID_REQUEST,
          "Content of parameter redirect_uri [" + redirectUri + "] not found in entity statement. ",
          HttpStatus.BAD_REQUEST);
    }
  }

  public static void verifyRequestedScopesListedInEntityStmnt(
      final JsonWebToken entityStmntRp, final String scopeParameter) {
    final List<String> scopesFromEntityStatementRp =
        EntityStatementRpReader.getScopesFromEntityStatementRp(entityStmntRp);
    if (Arrays.stream(scopeParameter.split(" "))
        .anyMatch(scope -> !scopesFromEntityStatementRp.contains(scope))) {
      throw new GsiException(
          INVALID_SCOPE,
          "Content of parameter scope ["
              + scopeParameter
              + "] exceeds scopes found in entity statement. ",
          HttpStatus.BAD_REQUEST);
    }
  }
}
