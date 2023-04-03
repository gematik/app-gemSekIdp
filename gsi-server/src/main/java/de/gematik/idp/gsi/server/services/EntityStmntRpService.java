/*
 * Copyright (c) 2023 gematik GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an 'AS IS' BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.idp.gsi.server.services;

import static de.gematik.idp.data.fedidp.Oauth2ErrorCode.INVALID_REQUEST;

import de.gematik.idp.IdpConstants;
import de.gematik.idp.crypto.CryptoLoader;
import de.gematik.idp.crypto.EcKeyUtility;
import de.gematik.idp.data.fedidp.Oauth2ErrorCode;
import de.gematik.idp.gsi.server.ServerUrlService;
import de.gematik.idp.gsi.server.exceptions.GsiException;
import de.gematik.idp.token.JsonWebToken;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import kong.unirest.HttpResponse;
import kong.unirest.Unirest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

/** EntityStmntRpService = managed EntityStatement of relying parties */
@Slf4j
@Service
@RequiredArgsConstructor
public class EntityStmntRpService {

  @Autowired ResourceReader resourceReader;
  /** Entity statements delivered by Fachdienst */
  private static final Map<String, String> ENTITY_STATEMENTS_OF_FACHDIENST;
  /** Entity statements about Fachdienste. Delivered by Fedmaster. */
  private static final Map<String, String> ENTITY_STATEMENTS_FEDMASTER_ABOUT_FACHDIENST;

  private final ServerUrlService serverUrlService;

  static {
    ENTITY_STATEMENTS_OF_FACHDIENST = new HashMap<>();
    ENTITY_STATEMENTS_FEDMASTER_ABOUT_FACHDIENST = new HashMap<>();
  }

  public static void verifySignature(final String jwsRawString, final PublicKey publicKey) {
    final JsonWebToken jsonWebToken = new JsonWebToken(jwsRawString);
    jsonWebToken.verify(publicKey);
  }

  /**
   * no exception -> client is registered
   *
   * @param urlRp URL of relying party
   */
  public void doAutoregistration(final String urlRp) {
    // Msg 2a and 2b
    // Msg 2c and 2d
    getEntityStatementRp(urlRp);
  }

  /**
   * @param issuerRp Issuer relying party
   * @return
   */
  public String getEntityStatementRp(final String issuerRp) {
    log.info("Entitystatement for RP [{}] requested.", issuerRp);
    updateStatementRpIfExpiredAndNewIsAvailable(issuerRp);
    return ENTITY_STATEMENTS_OF_FACHDIENST.get(issuerRp);
  }

  /**
   * Update Entity statement about a relying party, from Fedmaster.
   *
   * @param sub Issuer of requested relying party
   * @return
   */
  public String getEntityStatementAboutRp(final String sub) {
    updateStatementAboutRpIfExpiredAndNewIsAvailable(sub);
    return ENTITY_STATEMENTS_FEDMASTER_ABOUT_FACHDIENST.get(sub);
  }

  public static List<String> getRedirectUrisEntityStatementRp(final String entityStmntRp) {
    final Map<String, Object> bodyClaims = new JsonWebToken(entityStmntRp).getBodyClaims();
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
  public void verifyRedirectUriExistsInEntityStmnt(
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
    if (ENTITY_STATEMENTS_OF_FACHDIENST.containsKey(issuer)) {
      if (stmntIsEpired(ENTITY_STATEMENTS_OF_FACHDIENST.get(issuer))) {
        fetchEntityStatementRp(issuer);
      }
      return;
    }
    fetchEntityStatementRp(issuer);
  }

  private void updateStatementAboutRpIfExpiredAndNewIsAvailable(final String sub) {
    if (ENTITY_STATEMENTS_FEDMASTER_ABOUT_FACHDIENST.containsKey(sub)) {
      if (stmntIsEpired(ENTITY_STATEMENTS_FEDMASTER_ABOUT_FACHDIENST.get(sub))) {
        fetchEntityStatementAboutRp(sub);
      }
      return;
    }
    fetchEntityStatementAboutRp(sub);
  }

  private boolean stmntIsEpired(final String entityStmnt) {
    final Map<String, Object> bodyClaims = new JsonWebToken(entityStmnt).getBodyClaims();
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
      final String entityStmnt = resp.getBody();
      verifyEntityStmntRp(entityStmnt, issuer);
      ENTITY_STATEMENTS_OF_FACHDIENST.put(issuer, entityStmnt);
    } else {
      log.info(resp.getBody());
      throw new GsiException(
          Oauth2ErrorCode.INVALID_REQUEST,
          "No entity statement from relying party ["
              + issuer
              + "] available. Reason: "
              + resp.getBody()
              + HttpStatus.valueOf(resp.getStatus()),
          HttpStatus.BAD_REQUEST);
    }
  }

  private void verifyEntityStmntRp(final String entityStmnt, final String issuer) {
    final String esAboutRp = getEntityStatementAboutRp(issuer);
    verifySignature(entityStmnt, getRpSigKey(esAboutRp));
  }

  private void fetchEntityStatementAboutRp(final String sub) {
    final String entityIdentifierFedmaster = serverUrlService.determineFedmasterUrl();
    log.info("FedmasterUrl: " + entityIdentifierFedmaster);
    final HttpResponse<String> resp =
        Unirest.get(
                serverUrlService.determineFedmasterUrl()
                    + IdpConstants.FEDMASTER_FEDERATION_FETCH_ENDPOINT)
            .queryString("iss", entityIdentifierFedmaster)
            .queryString("sub", sub)
            .asString();
    if (resp.getStatus() == HttpStatus.OK.value()) {
      verifySignature(resp.getBody(), getFedmasterSigKey());
      ENTITY_STATEMENTS_FEDMASTER_ABOUT_FACHDIENST.put(sub, resp.getBody());
    } else {
      log.info(resp.getBody());
      throw new GsiException(
          Oauth2ErrorCode.INVALID_REQUEST,
          "No entity statement for relying party ["
              + sub
              + "] at Fedmaster available. Reason: "
              + resp.getBody()
              + HttpStatus.valueOf(resp.getStatus()),
          HttpStatus.BAD_REQUEST);
    }
  }

  private PublicKey getFedmasterSigKey() {
    return CryptoLoader.getCertificateFromPem(
            resourceReader.getFileFromResourceAsBytes("cert/fedmaster-sig.pem"))
        .getPublicKey();
  }

  private PublicKey getRpSigKey(final String entityStmntAboutRp) {
    final Map<String, Object> keyMap =
        (Map<String, Object>) new JsonWebToken(entityStmntAboutRp).getBodyClaims().get("jwks");
    final List<Map<String, String>> keyList = (List<Map<String, String>>) keyMap.get("keys");
    final Map<String, String> rpSigKeyValues = keyList.get(0);
    return createEcPubKey(rpSigKeyValues);
  }

  private PublicKey createEcPubKey(final Map<String, String> rpSigKeyValues) {
    try {
      return EcKeyUtility.genECPublicKey(
          rpSigKeyValues.get("crv"), rpSigKeyValues.get("x"), rpSigKeyValues.get("y"));
    } catch (final NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException e) {
      throw new GsiException("Creation of ECPublicKey failed", e);
    }
  }
}
