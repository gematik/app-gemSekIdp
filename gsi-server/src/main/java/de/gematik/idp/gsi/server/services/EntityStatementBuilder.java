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

import static de.gematik.idp.IdpConstants.FED_AUTH_ENDPOINT;
import static de.gematik.idp.IdpConstants.TOKEN_ENDPOINT;
import static de.gematik.idp.gsi.server.data.GsiConstants.FEDIDP_PAR_AUTH_ENDPOINT;
import static de.gematik.idp.gsi.server.data.GsiConstants.FED_SIGNED_JWKS_ENDPOINT;
import static de.gematik.idp.gsi.server.data.GsiConstants.LOGO_URI;
import static de.gematik.idp.gsi.server.data.GsiConstants.SCOPES_SUPPORTED;
import static de.gematik.idp.gsi.server.util.ClaimHelper.getClaimsForScopeSet;

import de.gematik.idp.data.FederationPubKey;
import de.gematik.idp.data.JwtHelper;
import de.gematik.idp.gsi.server.data.EntityStatement;
import de.gematik.idp.gsi.server.data.FederationEntity;
import de.gematik.idp.gsi.server.data.Metadata;
import de.gematik.idp.gsi.server.data.OpenidProvider;
import de.gematik.idp.gsi.server.data.RequestAuthenticationMethodsSupported;
import java.time.ZonedDateTime;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;

@RequiredArgsConstructor
public class EntityStatementBuilder {

  private static final int ENTITY_STATEMENT_TTL_HOURS = 2;
  @Autowired FederationPubKey esSigPubKey;

  public EntityStatement buildEntityStatement(
      final String serverUrl, final String serverUrlMtls, final String fedmasterUrl) {
    final ZonedDateTime currentTime = ZonedDateTime.now();
    return buildEntityStatement(
        serverUrl,
        serverUrlMtls,
        fedmasterUrl,
        currentTime.plusHours(ENTITY_STATEMENT_TTL_HOURS).toEpochSecond());
  }

  public EntityStatement buildEntityStatement(
      final String serverUrl,
      final String serverUrlMtls,
      final String fedmasterUrl,
      final long expSeconds) {
    final ZonedDateTime currentTime = ZonedDateTime.now();
    return EntityStatement.builder()
        .exp(expSeconds)
        .iat(currentTime.toEpochSecond())
        .iss(serverUrl)
        .sub(serverUrl)
        .jwks(JwtHelper.getJwks(esSigPubKey))
        .authorityHints(new String[] {fedmasterUrl})
        .metadata(buildMetadata(serverUrl, serverUrlMtls))
        .build();
  }

  private Metadata buildMetadata(final String serverUrl, final String serverUrlMtls) {
    final OpenidProvider openidProvider =
        OpenidProvider.builder()
            .issuer(serverUrl)
            .signedJwksUri(serverUrl + FED_SIGNED_JWKS_ENDPOINT)
            .organizationName("gematik sektoraler IDP")
            .logoUri(LOGO_URI)
            .authorizationEndpoint(serverUrl + FED_AUTH_ENDPOINT)
            .tokenEndpoint(serverUrlMtls + TOKEN_ENDPOINT)
            .pushedAuthorizationRequestEndpoint(serverUrlMtls + FEDIDP_PAR_AUTH_ENDPOINT)
            .clientRegistrationTypesSupported(new String[] {"automatic"})
            .subjectTypesSupported(new String[] {"pairwise"})
            .responseTypesSupported(new String[] {"code"})
            .scopesSupported(SCOPES_SUPPORTED.toArray(String[]::new))
            .responseModesSupported(new String[] {"query"})
            .grantTypesSupported(new String[] {"authorization_code"})
            .requirePushedAuthorizationRequests(true)
            .tokenEndpointAuthMethodsSupported(new String[] {"self_signed_tls_client_auth"})
            .requestAuthenticationMethodsSupported(
                RequestAuthenticationMethodsSupported.builder()
                    .ar(new String[] {"none"})
                    .par(new String[] {"self_signed_tls_client_auth"})
                    .build())
            .idTokenSigningAlgValuesSupported(new String[] {"ES256"})
            .idTokenEncryptionAlgValuesSupported(new String[] {"ECDH-ES"})
            .idTokenEncryptionEncValuesSupported(new String[] {"A256GCM"})
            .userTypeSupported(new String[] {"IP"})
            .claimsSupported(getClaimsForScopeSet(SCOPES_SUPPORTED).toArray(String[]::new))
            .claimsParameterSupported(true)
            .build();
    final FederationEntity federationEntity =
        FederationEntity.builder()
            .name("gematik sektoraler IDP")
            .contacts(new String[] {"support@idp4711.de", "idm@gematik.de"})
            .homepageUri("https://idp4711.de")
            .build();
    return Metadata.builder()
        .openidProvider(openidProvider)
        .federationEntity(federationEntity)
        .build();
  }
}
