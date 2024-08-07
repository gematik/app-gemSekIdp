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

import de.gematik.idp.IdpConstants;
import de.gematik.idp.gsi.server.data.GsiConstants;
import de.gematik.idp.gsi.server.exceptions.GsiException;
import de.gematik.idp.token.JsonWebToken;
import de.gematik.idp.token.TokenClaimExtraction;
import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import kong.unirest.core.HttpResponse;
import kong.unirest.core.Unirest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.lang.JoseException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

/** EntityStmntRpService = managed EntityStatement of relying parties */
@Slf4j
@Service
@RequiredArgsConstructor
public class EntityStatementRpService {

  private final PublicKey fedmasterSigKey;
  private final ServerUrlService serverUrlService;

  /** Entity statements delivered by Fachdienst */
  private final Map<String, JsonWebToken> entityStatementsOfFachdienst = new HashMap<>();

  /** Entity statements about Fachdienste. Delivered by Fedmaster. */
  private final Map<String, JsonWebToken> entityStatementsFedmasterAboutFachdienst =
      new HashMap<>();

  /**
   * no exception -> client is registered
   *
   * @param clientId URL of relying party
   */
  public void doAutoregistration(
      final String clientId, final String redirectUri, final String scope) {
    // Msg 2a and 2b
    // Msg 2c and 2d
    log.debug("Autoregistration started...");
    getEntityStatementRp(clientId);
    verifyRedirectUriExistsInEntityStmnt(clientId, redirectUri);
    verifyRequestedScopesListedInEntityStmnt(clientId, scope);
    verifyIdpDoesSupportRequestedScopes(scope);
    log.debug("Autoregistration done.");
  }

  /**
   * @param issuerRp name and url of the fachdienst/relying party
   * @return the entity statement issued by the fachdienst/relying party
   */
  public JsonWebToken getEntityStatementRp(final String issuerRp) {
    log.debug("Entitystatement of RP [{}] requested.", issuerRp);
    updateStatementRpIfExpiredAndNewIsAvailable(issuerRp);
    log.debug(
        "Entitystatement of RP [{}] stored. JWT: {}",
        issuerRp,
        entityStatementsOfFachdienst.get(issuerRp).getRawString());
    return entityStatementsOfFachdienst.get(issuerRp);
  }

  /**
   * Update entity statement about a relying party, from Fedmaster.
   *
   * @param sub identifier of the fachdienst/relying party
   * @return the entity statement about the fachdienst/relying party issued by the fed master
   */
  public JsonWebToken getEntityStatementAboutRp(final String sub) {
    updateStatementAboutRpIfExpiredAndNewIsAvailable(sub);
    return entityStatementsFedmasterAboutFachdienst.get(sub);
  }

  public X509Certificate getRpTlsClientCert(final String sub) throws JoseException {
    final Optional<X509Certificate> tlsClientCertFromEntityStatement =
        getRpTlsClientCertFromEntityStatement(sub);
    if (tlsClientCertFromEntityStatement.isPresent()) {
      log.debug("Found TLS client certificate in entity statement of [{}].", sub);
      return tlsClientCertFromEntityStatement.get();
    }
    return getRpTlsClientCertFromSignedJwks(sub)
        .orElseThrow(
            () ->
                new GsiException(
                    INVALID_REQUEST,
                    "TLS client certificate for relying party not found",
                    HttpStatus.BAD_REQUEST));
  }

  private Optional<X509Certificate> getRpTlsClientCertFromEntityStatement(final String sub) {
    try {
      final Optional<List<Map<String, Object>>> keyList = getKeyListFromEntityStatement(sub);
      if (keyList.isPresent()) {
        final Optional<Map<String, Object>> certKeyAsMap =
            keyList.get().stream()
                .filter(key -> key.containsKey("use") && key.containsKey("x5c"))
                .filter(key -> key.get("use").equals("sig"))
                .findFirst();
        if (certKeyAsMap.isPresent()) {
          final List<String> certList = (List<String>) certKeyAsMap.get().get("x5c");
          if (certList.size() > 1) {
            throw new GsiException(
                INVALID_REQUEST, "More than one x5c certificate found", HttpStatus.UNAUTHORIZED);
          }
          return certList.stream().findFirst().map(this::transformStringToX509Certificate);
        }
      }
      return Optional.empty();
    } catch (final NullPointerException | ClassCastException e) {
      return Optional.empty();
    }
  }

  private Optional<X509Certificate> getRpTlsClientCertFromSignedJwks(final String sub) {
    try {
      log.debug("Search TLS client certificate in signed JWKS of RP [{}]).", sub);
      final Optional<List<Map<String, Object>>> keyList = getKeyListFromSignedJwks(sub);
      if (keyList.isPresent()) {
        final Optional<Map<String, Object>> certKeyAsMap =
            keyList.get().stream()
                .filter(key -> key.containsKey("use") && key.containsKey("x5c"))
                .filter(key -> key.get("use").equals("sig"))
                .findFirst();
        if (certKeyAsMap.isPresent()) {
          log.debug("Found client certificate in signed JWKS of RP [{}]).", sub);
          final List<String> certList = (List<String>) certKeyAsMap.get().get("x5c");
          if (certList.size() > 1) {
            throw new GsiException(
                INVALID_REQUEST, "More than one x5c certificate", HttpStatus.UNAUTHORIZED);
          }
          return certList.stream().findFirst().map(this::transformStringToX509Certificate);
        }
      }
      return Optional.empty();
    } catch (final NullPointerException | ClassCastException e) {
      return Optional.empty();
    }
  }

  private X509Certificate transformStringToX509Certificate(final String certAsString) {
    final byte[] encodedCert = Base64.getDecoder().decode(certAsString);
    final ByteArrayInputStream inputStream = new ByteArrayInputStream(encodedCert);

    final CertificateFactory certFactory;
    final X509Certificate cert;
    try {
      certFactory = CertificateFactory.getInstance("X.509");
      cert = (X509Certificate) certFactory.generateCertificate(inputStream);
    } catch (final CertificateException e) {
      throw new GsiException(
          INVALID_REQUEST,
          "entry of x5c-element in signed_jwks/entity statement is not a valid x509-certificate",
          HttpStatus.UNAUTHORIZED);
    }
    return cert;
  }

  public PublicJsonWebKey getRpEncKey(final String sub) throws JoseException {
    final Optional<PublicJsonWebKey> encKeyFromEntityStatement =
        getRpEncKeyFromEntityStatement(sub);
    if (encKeyFromEntityStatement.isPresent()) {
      log.debug("Found encryption key in entity statement of [{}].", sub);
      return encKeyFromEntityStatement.get();
    }
    return getRpEncKeyFromSignedJwks(sub)
        .orElseThrow(
            () ->
                new GsiException(
                    INVALID_REQUEST,
                    "Encryption key for relying party not found",
                    HttpStatus.BAD_REQUEST));
  }

  private Optional<PublicJsonWebKey> getRpEncKeyFromEntityStatement(final String sub) {
    try {
      final Optional<List<Map<String, Object>>> keyList = getKeyListFromEntityStatement(sub);
      if (keyList.isPresent()) {
        final Optional<Map<String, Object>> encKeyAsMap =
            keyList.get().stream()
                .filter(key -> key.containsKey("use"))
                .filter(key -> key.get("use").equals("enc"))
                .findFirst();
        if (encKeyAsMap.isPresent()) {
          return Optional.of(PublicJsonWebKey.Factory.newPublicJwk(encKeyAsMap.get()));
        }
      }
      return Optional.empty();
    } catch (final JoseException | NullPointerException | ClassCastException e) {
      return Optional.empty();
    }
  }

  private Optional<PublicJsonWebKey> getRpEncKeyFromSignedJwks(final String sub) {
    try {
      log.debug("Search encryption key in signed JWKS of RP [{}]).", sub);
      final Optional<List<Map<String, Object>>> keyList = getKeyListFromSignedJwks(sub);
      if (keyList.isPresent()) {
        final Optional<Map<String, Object>> encKeyAsMap =
            keyList.get().stream()
                .filter(key -> key.containsKey("use"))
                .filter(key -> key.get("use").equals("enc"))
                .findFirst();
        if (encKeyAsMap.isPresent()) {
          log.debug("Found encryption key in signed JWKS of RP [{}]).", sub);
          return Optional.of(PublicJsonWebKey.Factory.newPublicJwk(encKeyAsMap.get()));
        }
      }
      return Optional.empty();
    } catch (final JoseException | NullPointerException | ClassCastException e) {
      return Optional.empty();
    }
  }

  private Optional<JsonWebToken> getSignedJwks(final String sub) {
    final Optional<String> rpSignedJwksUri =
        serverUrlService.determineSignedJwksUri(getEntityStatementRp(sub));
    if (rpSignedJwksUri.isPresent()) {
      final HttpResponse<String> resp = Unirest.get(rpSignedJwksUri.get()).asString();
      if (resp.isSuccess()) {
        // TODO check signature
        return Optional.of(new JsonWebToken(resp.getBody()));
      }
    }
    return Optional.empty();
  }

  private Optional<List<Map<String, Object>>> getKeyListFromEntityStatement(final String sub) {
    final JsonWebToken entityStmntRp = getEntityStatementRp(sub);
    final Map<String, Object> metadata =
        (Map<String, Object>) entityStmntRp.getBodyClaims().get("metadata");
    final Map<String, Object> openidRelyingParty =
        (Map<String, Object>) metadata.get("openid_relying_party");
    if (openidRelyingParty.containsKey("jwks")) {
      log.debug(
          "Key [jwks] found in openid_relying_party (inside Entitystatement of RP [{}]).", sub);
      final Map<String, Object> jwksMap = (Map<String, Object>) openidRelyingParty.get("jwks");
      final List<Map<String, Object>> keyList = (List<Map<String, Object>>) jwksMap.get("keys");
      return Optional.of(keyList);
    }
    return Optional.empty();
  }

  private Optional<List<Map<String, Object>>> getKeyListFromSignedJwks(final String sub) {
    final Optional<JsonWebToken> signedJwks = getSignedJwks(sub);
    if (signedJwks.isPresent()) {
      final List<Map<String, Object>> keyList =
          (List<Map<String, Object>>) signedJwks.get().getBodyClaims().get("keys");
      return Optional.of(keyList);
    }
    return Optional.empty();
  }

  private static List<String> getRedirectUrisEntityStatementRp(final JsonWebToken entityStmntRp) {
    final Map<String, Object> bodyClaims = entityStmntRp.getBodyClaims();
    final Map<String, Object> metadata =
        Objects.requireNonNull(
            (Map<String, Object>) bodyClaims.get("metadata"), "missing claim: metadata");
    final Map<String, Object> openidRelyingParty =
        Objects.requireNonNull(
            (Map<String, Object>) metadata.get("openid_relying_party"),
            "missing claim: openid_relying_party");
    return Objects.requireNonNull(
        (List<String>) openidRelyingParty.get("redirect_uris"), "missing claim: redirect_uris");
  }

  private static List<String> getScopesFromEntityStatementRp(final JsonWebToken entityStmntRp) {
    final Map<String, Object> bodyClaims = entityStmntRp.getBodyClaims();
    final Map<String, Object> metadata =
        Objects.requireNonNull(
            (Map<String, Object>) bodyClaims.get("metadata"), "missing claim: metadata");
    final Map<String, Object> openidRelyingParty =
        Objects.requireNonNull(
            (Map<String, Object>) metadata.get("openid_relying_party"),
            "missing claim: openid_relying_party");
    return Arrays.stream(
            Objects.requireNonNull((String) openidRelyingParty.get("scope"), "missing claim: scope")
                .split(" "))
        .toList();
  }

  /**
   * @param fachdienstClientId
   * @param redirectUri
   */
  private void verifyRedirectUriExistsInEntityStmnt(
      final String fachdienstClientId, final String redirectUri) {
    if (getRedirectUrisEntityStatementRp(getEntityStatementRp(fachdienstClientId)).stream()
        .noneMatch(entry -> entry.equals(redirectUri))) {
      throw new GsiException(
          INVALID_REQUEST,
          "Content of parameter redirect_uri [" + redirectUri + "] not found in entity statement. ",
          HttpStatus.BAD_REQUEST);
    }
  }

  private void verifyRequestedScopesListedInEntityStmnt(
      final String fachdienstClientId, final String scopeParameter) {
    final List<String> scopesFromEntityStatementRp =
        getScopesFromEntityStatementRp(getEntityStatementRp(fachdienstClientId));
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

  private void verifyIdpDoesSupportRequestedScopes(final String scopeParameter) {
    final Set<String> requestedScopes =
        Arrays.stream(scopeParameter.split(" ")).collect(Collectors.toSet());

    if (!(GsiConstants.SCOPES_SUPPORTED.containsAll(requestedScopes))) {
      throw new GsiException(
          INVALID_SCOPE, "More scopes requested in PAR than supported.", HttpStatus.BAD_REQUEST);
    }
  }

  private void updateStatementRpIfExpiredAndNewIsAvailable(final String issuer) {
    if (entityStatementsOfFachdienst.containsKey(issuer)) {
      if (stmntIsEpired(entityStatementsOfFachdienst.get(issuer))) {
        log.debug("Entitystatement of RP [{}] is in storage but expired. Fetching...", issuer);
        fetchEntityStatementRp(issuer);
      } else {
        log.debug("Entitystatement of RP [{}] is in storage and not expired.", issuer);
      }
      return;
    }
    log.debug("Entitystatement of RP [{}] not found in storage. Fetching...", issuer);
    fetchEntityStatementRp(issuer);
  }

  private void updateStatementAboutRpIfExpiredAndNewIsAvailable(final String sub) {
    if (entityStatementsFedmasterAboutFachdienst.containsKey(sub)) {
      if (stmntIsEpired(entityStatementsFedmasterAboutFachdienst.get(sub))) {
        log.debug("Entitystatement about RP [{}] is in storage but expired. Fetching...", sub);
        fetchEntityStatementAboutRp(sub);
      } else {
        log.debug("Entitystatement about RP [{}] is in storage and not expired.", sub);
      }
      return;
    }
    log.debug("Entitystatement about RP [{}] not found in storage. Fetching...", sub);
    fetchEntityStatementAboutRp(sub);
  }

  private boolean stmntIsEpired(final JsonWebToken entityStmnt) {
    final Map<String, Object> bodyClaims = entityStmnt.getBodyClaims();
    final Long exp = (Long) bodyClaims.get("exp");
    return isExpired(exp);
  }

  private boolean isExpired(final Long exp) {
    final ZonedDateTime currentUtcTime = ZonedDateTime.now(ZoneOffset.UTC);
    final ZonedDateTime expiredUtcTime =
        ZonedDateTime.ofInstant(Instant.ofEpochSecond(exp), ZoneOffset.UTC);
    return currentUtcTime.isAfter(expiredUtcTime);
  }

  private void fetchEntityStatementRp(final String issuer) {
    final HttpResponse<String> resp =
        Unirest.get(issuer + IdpConstants.ENTITY_STATEMENT_ENDPOINT).asString();
    if (resp.getStatus() == HttpStatus.OK.value()) {
      final JsonWebToken entityStmnt = new JsonWebToken(resp.getBody());
      verifyEntityStmntRp(entityStmnt, issuer);
      entityStatementsOfFachdienst.put(issuer, entityStmnt);
      log.debug(
          "Entitystatement of RP [{}] stored. JWT: {}",
          issuer,
          entityStatementsOfFachdienst.get(issuer).getRawString());
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

  private void verifyEntityStmntRp(final JsonWebToken entityStmnt, final String issuer) {
    final String keyIdSigEntStmnt = (String) entityStmnt.getHeaderClaims().get("kid");
    final JsonWebToken esAboutRp = getEntityStatementAboutRp(issuer);
    final JsonWebKeySet jwks = TokenClaimExtraction.extractJwksFromBody(esAboutRp.getRawString());
    entityStmnt.verify(TokenClaimExtraction.getECPublicKey(jwks, keyIdSigEntStmnt));
  }

  private void fetchEntityStatementAboutRp(final String sub) {
    final String entityIdentifierFedmaster = serverUrlService.determineFedmasterUrl();
    log.info("FedmasterUrl: " + entityIdentifierFedmaster);
    final HttpResponse<String> resp =
        Unirest.get(serverUrlService.determineFetchEntityStatementEndpoint())
            .queryString("iss", entityIdentifierFedmaster)
            .queryString("sub", sub)
            .asString();
    if (resp.getStatus() == HttpStatus.OK.value()) {
      final JsonWebToken entityStatementAboutRp = new JsonWebToken(resp.getBody());
      entityStatementAboutRp.verify(fedmasterSigKey);
      entityStatementsFedmasterAboutFachdienst.put(sub, entityStatementAboutRp);
      log.debug(
          "Entitystatement about RP [{}] stored. JWT: {}",
          sub,
          entityStatementsFedmasterAboutFachdienst.get(sub).getRawString());
    } else {
      log.info(resp.getBody());
      throw new GsiException(
          INVALID_REQUEST,
          "No entity statement about relying party ["
              + sub
              + "] at Fedmaster iss: "
              + entityIdentifierFedmaster
              + " available. Reason: "
              + resp.getBody()
              + HttpStatus.valueOf(resp.getStatus()),
          HttpStatus.BAD_REQUEST);
    }
  }
}
