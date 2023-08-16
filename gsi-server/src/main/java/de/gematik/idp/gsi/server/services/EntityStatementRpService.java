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
import de.gematik.idp.crypto.CryptoLoader;
import de.gematik.idp.gsi.server.exceptions.GsiException;
import de.gematik.idp.token.JsonWebToken;
import de.gematik.idp.token.TokenClaimExtraction;
import java.security.PublicKey;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import kong.unirest.HttpResponse;
import kong.unirest.Unirest;
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

  private final ResourceReader resourceReader;
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
  public void doAutoregistration(final String clientId, final String redirectUri) {
    // Msg 2a and 2b
    // Msg 2c and 2d
    getEntityStatementRp(clientId);
    verifyRedirectUriExistsInEntityStmnt(clientId, redirectUri);
  }

  /**
   * @param issuerRp name and url of the fachdienst/relying party
   * @return the entity statement issued by the fachdienst/relying party
   */
  public JsonWebToken getEntityStatementRp(final String issuerRp) {
    log.info("Entitystatement for RP [{}] requested.", issuerRp);
    updateStatementRpIfExpiredAndNewIsAvailable(issuerRp);
    return entityStatementsOfFachdienst.get(issuerRp);
  }

  /**
   * Update Entity statement about a relying party, from Fedmaster.
   *
   * @param sub identifier of the fachdienst/relying party
   * @return the entity statement about the fachdienst/relying party issued by the fed master
   */
  public JsonWebToken getEntityStatementAboutRp(final String sub) {
    updateStatementAboutRpIfExpiredAndNewIsAvailable(sub);
    return entityStatementsFedmasterAboutFachdienst.get(sub);
  }

  public PublicJsonWebKey getRpEncKey(final String sub) throws JoseException {
    final Optional<PublicJsonWebKey> encKeyFromEntityStatement =
        getRpEncKeyFromEntityStatement(sub);
    if (encKeyFromEntityStatement.isPresent()) {
      return encKeyFromEntityStatement.get();
    }
    return getRpEncKeyFromSignedJwks(sub)
        .orElseThrow(
            () ->
                new GsiException(
                    INVALID_REQUEST, "No Relying Party Enc Key found", HttpStatus.BAD_REQUEST));
  }

  private Optional<PublicJsonWebKey> getRpEncKeyFromEntityStatement(final String sub)
      throws JoseException {
    final JsonWebToken entityStmntRp = getEntityStatementRp(sub);
    final Map<String, Object> metadata =
        (Map<String, Object>) entityStmntRp.getBodyClaims().get("metadata");
    final Map<String, Object> openidRelyingParty =
        Objects.requireNonNull(
            (Map<String, Object>) metadata.get("openid_relying_party"),
            "missing claim: openid_relying_party");

    if (openidRelyingParty.containsKey("jwks")) {
      final Map<String, Object> jwksMap = (Map<String, Object>) openidRelyingParty.get("jwks");
      final List<Map<String, Object>> keyList = (List<Map<String, Object>>) jwksMap.get("keys");
      final Optional<Map<String, Object>> encKeyAsMap =
          keyList.stream().filter(key -> key.get("use").equals("enc")).findFirst();
      if (encKeyAsMap.isPresent()) {
        return Optional.of(PublicJsonWebKey.Factory.newPublicJwk(encKeyAsMap.get()));
      }
    }
    return Optional.empty();
  }

  private Optional<PublicJsonWebKey> getRpEncKeyFromSignedJwks(final String sub)
      throws JoseException {
    final Optional<JsonWebToken> signedJwks = getSignedJwks(sub);
    if (signedJwks.isPresent()) {
      final Map<String, Object> jwksMap =
          (Map<String, Object>) signedJwks.get().getBodyClaims().get("jwks");
      final List<Map<String, Object>> keyList = (List<Map<String, Object>>) jwksMap.get("keys");
      final Optional<Map<String, Object>> encKeyAsMap =
          keyList.stream().filter(key -> key.get("use").equals("enc")).findFirst();
      if (encKeyAsMap.isPresent()) {
        return Optional.of(PublicJsonWebKey.Factory.newPublicJwk(encKeyAsMap.get()));
      }
    }
    return Optional.empty();
  }

  private Optional<JsonWebToken> getSignedJwks(final String sub) {
    final Optional<String> rpSignedJwksUri =
        serverUrlService.determineSignedJwsUri(getEntityStatementRp(sub));
    if (rpSignedJwksUri.isPresent()) {
      final HttpResponse<String> resp = Unirest.get(rpSignedJwksUri.get()).asString();
      if (resp.isSuccess()) {
        // TODO check signature
        return Optional.of(new JsonWebToken(resp.getBody()));
      }
      // TODO handle else case
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

  private void updateStatementRpIfExpiredAndNewIsAvailable(final String issuer) {
    if (entityStatementsOfFachdienst.containsKey(issuer)) {
      if (stmntIsEpired(entityStatementsOfFachdienst.get(issuer))) {
        fetchEntityStatementRp(issuer);
      }
      return;
    }
    fetchEntityStatementRp(issuer);
  }

  private void updateStatementAboutRpIfExpiredAndNewIsAvailable(final String sub) {
    if (entityStatementsFedmasterAboutFachdienst.containsKey(sub)) {
      if (stmntIsEpired(entityStatementsFedmasterAboutFachdienst.get(sub))) {
        fetchEntityStatementAboutRp(sub);
      }
      return;
    }
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
      entityStatementsOfFachdienst.put(
          issuer, entityStmnt); // TODO: hier nicht als string sondern als entityStatementObjekt
    } else {
      log.info(resp.getBody());
      throw new GsiException(
          INVALID_REQUEST,
          "No entity statement from relying party ["
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
      entityStatementAboutRp.verify(getFedmasterSigKey());
      entityStatementsFedmasterAboutFachdienst.put(sub, entityStatementAboutRp);
    } else {
      log.info(resp.getBody());
      throw new GsiException(
          INVALID_REQUEST,
          "No entity statement for relying party ["
              + sub
              + "] at Fedmaster iss: "
              + entityIdentifierFedmaster
              + " available. Reason: "
              + resp.getBody()
              + HttpStatus.valueOf(resp.getStatus()),
          HttpStatus.BAD_REQUEST);
    }
  }

  private PublicKey getFedmasterSigKey() {
    return CryptoLoader.getCertificateFromPem(
            resourceReader.getFileFromResourceAsBytes("cert/fedmaster-sig-TU.pem"))
        .getPublicKey();
  }
}
