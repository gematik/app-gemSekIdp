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

package de.gematik.idp.gsi.server.services;

import static de.gematik.idp.data.Oauth2ErrorCode.INVALID_REQUEST;
import static de.gematik.idp.data.Oauth2ErrorCode.INVALID_SCOPE;
import static de.gematik.idp.data.Oauth2ErrorCode.UNAUTHORIZED_CLIENT;
import static de.gematik.idp.gsi.server.data.GsiConstants.ACR_HIGH;
import static de.gematik.idp.gsi.server.data.GsiConstants.ACR_SUBSTANTIAL;
import static de.gematik.idp.gsi.server.data.GsiConstants.ACR_VALUES;
import static de.gematik.idp.gsi.server.data.GsiConstants.AMR_VALUES;
import static de.gematik.idp.gsi.server.data.GsiConstants.AMR_VALUES_HIGH;
import static de.gematik.idp.gsi.server.data.GsiConstants.AMR_VALUES_SUBSTANTIAL;

import de.gematik.idp.crypto.CryptoLoader;
import de.gematik.idp.crypto.exceptions.IdpCryptoException;
import de.gematik.idp.field.ClientUtilities;
import de.gematik.idp.gsi.server.data.FedIdpAuthSession;
import de.gematik.idp.gsi.server.data.GsiConstants;
import de.gematik.idp.gsi.server.data.RpToken;
import de.gematik.idp.gsi.server.exceptions.GsiException;
import de.gematik.idp.token.JsonWebToken;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;

@Slf4j
public abstract class RequestValidator {

  public static void validateParParams(
      final JsonWebToken entityStmntAboutRp, final String redirectUri, final String scope) {
    // Msg 2a and 2b
    // Msg 2c and 2d
    EntityStatementRpVerifier.verifyRedirectUriExistsInEntityStmnt(entityStmntAboutRp, redirectUri);
    EntityStatementRpVerifier.verifyRequestedScopesListedInEntityStmnt(entityStmntAboutRp, scope);
    verifyIdpDoesSupportRequestedScopes(scope);
  }

  public static void validateCertificate(
      final String clientCert, final RpToken entityStmntRp, final boolean isRequiredClientCert) {
    if (clientCert == null) {
      if (isRequiredClientCert) {
        throw new GsiException(
            INVALID_REQUEST, "client certificate is missing", HttpStatus.BAD_REQUEST);
      }
    } else {
      try {
        final X509Certificate certFromRequest =
            CryptoLoader.getCertificateFromPem(
                java.net.URLDecoder.decode(clientCert, StandardCharsets.UTF_8).getBytes());
        final List<X509Certificate> certsFromEntityStatement =
            entityStmntRp.getRpTlsClientCertificates();
        if (certsFromEntityStatement.stream()
            .noneMatch(certFromEs -> certFromEs.equals(certFromRequest))) {
          throw new GsiException(
              UNAUTHORIZED_CLIENT,
              "client certificate in tls handshake does not match any certificate in entity"
                  + " statement/signed_jwks",
              HttpStatus.UNAUTHORIZED);
        }
      } catch (final IdpCryptoException e) {
        throw new GsiException(
            UNAUTHORIZED_CLIENT,
            "client certificate in tls handshake is not a valid x509 certificate",
            HttpStatus.UNAUTHORIZED);
      }
    }
  }

  public static void validateAuthRequestParams(
      final FedIdpAuthSession session, final String clientId) {
    final boolean clientIdBelongsToRequestUri = session.getFachdienstClientId().equals(clientId);
    if (!clientIdBelongsToRequestUri) {
      throw new GsiException(INVALID_REQUEST, "unknown client_id", HttpStatus.BAD_REQUEST);
    }
  }

  public static void verifyRedirectUri(final String redirectUri, final String sessionRedirectUri) {
    if (!redirectUri.equals(sessionRedirectUri)) {
      throw new GsiException(INVALID_REQUEST, "invalid redirect_uri", HttpStatus.BAD_REQUEST);
    }
  }

  public static void verifyCodeVerifier(final String codeVerifier, final String codeChallenge) {
    if (!ClientUtilities.generateCodeChallenge(codeVerifier).equals(codeChallenge)) {
      throw new GsiException(INVALID_REQUEST, "invalid code_verifier", HttpStatus.BAD_REQUEST);
    }
  }

  public static void verifyClientId(final String clientId, final String sessionClientId) {
    if (!sessionClientId.equals(clientId)) {
      throw new GsiException(INVALID_REQUEST, "invalid client_id", HttpStatus.BAD_REQUEST);
    }
  }

  protected static void verifyIdpDoesSupportRequestedScopes(final String scopeParameter) {
    final Set<String> requestedScopes =
        Arrays.stream(scopeParameter.split(" ")).collect(Collectors.toSet());

    if (!(GsiConstants.SCOPES_SUPPORTED.containsAll(requestedScopes))) {
      throw new GsiException(
          INVALID_SCOPE, "More scopes requested in PAR than supported.", HttpStatus.BAD_REQUEST);
    }
  }

  /**
   * work in progress validates amr and acr values and their combinations
   *
   * @param acr set contains values if they were set as essential in claims param
   * @param amr set contains values if they were set as essential in claims param
   */
  public static void validateAmrAcrCombination(final Set<String> acr, final Set<String> amr) {
    acr.forEach(
        acrValue -> {
          if (!ACR_VALUES.contains(acrValue)) {
            throw new GsiException(
                INVALID_REQUEST, "invalid acr value: " + acrValue, HttpStatus.BAD_REQUEST);
          }
        });
    amr.forEach(
        amrValue -> {
          if (!AMR_VALUES.contains(amrValue)) {
            throw new GsiException(
                INVALID_REQUEST, "invalid amr value: " + amrValue, HttpStatus.BAD_REQUEST);
          }
        });
    if (acr.isEmpty() || amr.isEmpty()) return;
    if (acr.contains(ACR_HIGH) && !acr.contains(ACR_SUBSTANTIAL)) {
      amr.forEach(
          value -> {
            if (!AMR_VALUES_HIGH.contains(value)) {
              throw new GsiException(
                  INVALID_REQUEST,
                  "invalid combination of essential values acr and amr",
                  HttpStatus.BAD_REQUEST);
            }
          });
    } else if (acr.contains(ACR_SUBSTANTIAL) && !acr.contains(ACR_HIGH)) {
      amr.forEach(
          value -> {
            if (!AMR_VALUES_SUBSTANTIAL.contains(value)) {
              throw new GsiException(
                  INVALID_REQUEST,
                  "invalid combination of essential values acr and amr",
                  HttpStatus.BAD_REQUEST);
            }
          });
    }
  }

  public static void validateRedirectUri(final String redirectUri) {
    try {
      new URI(redirectUri);
    } catch (final URISyntaxException e) {
      throw new GsiException(
          INVALID_REQUEST, "Invalid redirect uri: " + e.getMessage(), HttpStatus.BAD_REQUEST);
    }
  }
}
