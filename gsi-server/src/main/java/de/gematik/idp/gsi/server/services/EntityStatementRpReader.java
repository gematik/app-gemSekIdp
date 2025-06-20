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

import de.gematik.idp.gsi.server.exceptions.GsiException;
import de.gematik.idp.token.JsonWebToken;
import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;
import lombok.extern.slf4j.Slf4j;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.lang.JoseException;
import org.springframework.http.HttpStatus;

@Slf4j
public abstract class EntityStatementRpReader {

  public static List<String> getRedirectUrisEntityStatementRp(final JsonWebToken entityStmntRp) {
    final Map<String, Object> openidRelyingParty = getOpenidRelyingParty(entityStmntRp);
    return Objects.requireNonNull(
        (List<String>) openidRelyingParty.get("redirect_uris"), "missing claim: redirect_uris");
  }

  public static List<String> getScopesFromEntityStatementRp(final JsonWebToken entityStmntRp) {
    final Map<String, Object> openidRelyingParty = getOpenidRelyingParty(entityStmntRp);
    return Arrays.stream(
            Objects.requireNonNull((String) openidRelyingParty.get("scope"), "missing claim: scope")
                .split(" "))
        .toList();
  }

  public static PublicJsonWebKey getRpEncKey(final JsonWebToken entityStmntRp) {
    final Optional<PublicJsonWebKey> encKeyFromEntityStatement =
        EntityStatementRpReader.getRpEncKeyFromEntityStatement(entityStmntRp);
    if (encKeyFromEntityStatement.isPresent()) {
      return encKeyFromEntityStatement.get();
    }
    final Supplier<GsiException> gsiExceptionSupplier =
        () ->
            new GsiException(
                INVALID_REQUEST,
                "Encryption key for relying party not found",
                HttpStatus.BAD_REQUEST);
    final JsonWebToken signedJwks = getSignedJwks(entityStmntRp).orElseThrow(gsiExceptionSupplier);
    return getRpEncKeyFromSignedJwks(signedJwks).orElseThrow(gsiExceptionSupplier);
  }

  public static List<X509Certificate> getRpTlsClientCerts(final JsonWebToken entityStmntRp) {
    final Optional<List<X509Certificate>> tlsClientCertsFromEntityStatement =
        getRpTlsClientCertsFromEntityStatement(entityStmntRp);
    if (tlsClientCertsFromEntityStatement.isPresent()) {
      return tlsClientCertsFromEntityStatement.get();
    }
    final Supplier<GsiException> gsiExceptionSupplier =
        () ->
            new GsiException(
                INVALID_REQUEST,
                "No TLS client certificate for relying party found",
                HttpStatus.BAD_REQUEST);
    final JsonWebToken signedJwks = getSignedJwks(entityStmntRp).orElseThrow(gsiExceptionSupplier);
    return getRpTlsClientCertsFromSignedJwks(signedJwks).orElseThrow(gsiExceptionSupplier);
  }

  private static Optional<PublicJsonWebKey> getRpEncKeyFromEntityStatement(
      final JsonWebToken entityStmntRp) {
    final String sub = (String) entityStmntRp.getBodyClaims().get("sub");
    log.debug("Search encryption key in entity statement of RP [{}]).", sub);
    final Optional<List<Map<String, Object>>> keyList =
        getKeyListFromEntityStatement(entityStmntRp);
    final Optional<PublicJsonWebKey> encKeyFromKeyList = getEncKeyFromKeyList(keyList);
    if (encKeyFromKeyList.isPresent())
      log.debug("Found encryption key in entity statement of RP [{}]).", sub);
    return encKeyFromKeyList;
  }

  private static Optional<List<X509Certificate>> getRpTlsClientCertsFromEntityStatement(
      final JsonWebToken entityStmntRp) {
    final String sub = (String) entityStmntRp.getBodyClaims().get("sub");
    log.debug("Search TLS client certificate in entity statement of RP [{}]).", sub);
    final Optional<List<Map<String, Object>>> keyList =
        getKeyListFromEntityStatement(entityStmntRp);
    final Optional<List<X509Certificate>> certsFromKeyList = getCertsFromKeyList(keyList);
    if (certsFromKeyList.isPresent())
      log.debug("Found client certificates in entity statement of RP [{}]).", sub);
    return certsFromKeyList;
  }

  private static Optional<PublicJsonWebKey> getRpEncKeyFromSignedJwks(
      final JsonWebToken signedJwks) {
    final String sub = (String) signedJwks.getBodyClaims().get("sub");
    log.debug("Search encryption key in signed JWKS of RP [{}]).", sub);
    final Optional<List<Map<String, Object>>> keyList = getKeyListFromSignedJwks(signedJwks);
    final Optional<PublicJsonWebKey> encKeyFromKeyList = getEncKeyFromKeyList(keyList);
    if (encKeyFromKeyList.isPresent())
      log.debug("Found encryption key in signed JWKS of RP [{}]).", sub);
    return encKeyFromKeyList;
  }

  private static Optional<List<X509Certificate>> getRpTlsClientCertsFromSignedJwks(
      final JsonWebToken signedJwks) {
    final String sub = (String) signedJwks.getBodyClaims().get("sub");
    log.debug("Search TLS client certificate in signed JWKS of RP [{}]).", sub);
    final Optional<List<Map<String, Object>>> keyList = getKeyListFromSignedJwks(signedJwks);
    final Optional<List<X509Certificate>> certsFromKeyList = getCertsFromKeyList(keyList);
    if (certsFromKeyList.isPresent())
      log.debug("Found client certificates in signed JWKS of RP [{}]).", sub);
    return certsFromKeyList;
  }

  private static Optional<List<Map<String, Object>>> getKeyListFromEntityStatement(
      final JsonWebToken entityStmntRp) {
    final Map<String, Object> metadata =
        (Map<String, Object>) entityStmntRp.getBodyClaims().get("metadata");
    final Map<String, Object> openidRelyingParty =
        (Map<String, Object>) metadata.get("openid_relying_party");
    if (openidRelyingParty.containsKey("jwks")) {
      log.debug(
          "Key [jwks] found in openid_relying_party (inside Entitystatement of RP [{}]).",
          entityStmntRp.getBodyClaims().get("sub"));
      final Map<String, Object> jwksMap = (Map<String, Object>) openidRelyingParty.get("jwks");
      final List<Map<String, Object>> keyList = (List<Map<String, Object>>) jwksMap.get("keys");
      return Optional.of(keyList);
    }
    return Optional.empty();
  }

  private static Optional<List<Map<String, Object>>> getKeyListFromSignedJwks(
      final JsonWebToken signedJwks) {
    final List<Map<String, Object>> keyList =
        (List<Map<String, Object>>) signedJwks.getBodyClaims().get("keys");
    return Optional.of(keyList);
  }

  private static Optional<List<X509Certificate>> getCertsFromKeyList(
      final Optional<List<Map<String, Object>>> keyList) {
    if (keyList.isPresent()) {
      final List<Map<String, Object>> certKeys =
          keyList.get().stream()
              .filter(key -> key.containsKey("use") && key.containsKey("x5c"))
              .filter(key -> key.get("use").equals("sig"))
              .toList();
      if (!certKeys.isEmpty()) {
        final List<X509Certificate> x5cList =
            certKeys.stream().map(EntityStatementRpReader::extractX5cValueFromCert).toList();
        return Optional.of(x5cList);
      }
    }
    return Optional.empty();
  }

  private static Optional<PublicJsonWebKey> getEncKeyFromKeyList(
      final Optional<List<Map<String, Object>>> keyList) {
    if (keyList.isPresent()) {
      try {

        final Optional<Map<String, Object>> encKeyAsMap =
            keyList.get().stream()
                .filter(key -> key.containsKey("use"))
                .filter(key -> key.get("use").equals("enc"))
                .findFirst();
        if (encKeyAsMap.isPresent()) {
          return Optional.of(PublicJsonWebKey.Factory.newPublicJwk(encKeyAsMap.get()));
        }
      } catch (final JoseException e) {
        return Optional.empty();
      }
    }
    return Optional.empty();
  }

  private static X509Certificate extractX5cValueFromCert(final Map<String, Object> certKey) {
    final List<String> x5cValues = (List<String>) certKey.get("x5c");
    if (x5cValues.isEmpty()) {
      throw new GsiException(
          INVALID_REQUEST, "No x5c certificate found in jwk", HttpStatus.UNAUTHORIZED);
    } else if (x5cValues.size() > 1) {
      throw new GsiException(
          INVALID_REQUEST, "More than one x5c certificate found in jwk", HttpStatus.UNAUTHORIZED);
    } else return transformStringToX509Certificate(x5cValues.getFirst());
  }

  private static Optional<JsonWebToken> getSignedJwks(final JsonWebToken entityStmntRp) {
    final Optional<String> rpSignedJwksUri = ServerUrlService.determineSignedJwksUri(entityStmntRp);
    if (rpSignedJwksUri.isPresent()) {
      return HttpClient.fetchSignedJwks(rpSignedJwksUri.get());
    }
    return Optional.empty();
  }

  private static Map<String, Object> getOpenidRelyingParty(final JsonWebToken entityStmntRp) {
    final Map<String, Object> bodyClaims = entityStmntRp.getBodyClaims();
    final Map<String, Object> metadata =
        Objects.requireNonNull(
            (Map<String, Object>) bodyClaims.get("metadata"), "missing claim: metadata");
    return Objects.requireNonNull(
        (Map<String, Object>) metadata.get("openid_relying_party"),
        "missing claim: openid_relying_party");
  }

  private static X509Certificate transformStringToX509Certificate(final String certAsString) {
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
}
