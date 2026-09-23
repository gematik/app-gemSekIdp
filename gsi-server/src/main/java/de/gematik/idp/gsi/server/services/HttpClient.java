/*
 * Copyright (Change Date see Readme), gematik GmbH
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

import de.gematik.idp.IdpConstants;
import de.gematik.idp.gsi.server.data.RpToken;
import de.gematik.idp.gsi.server.exceptions.GsiException;
import de.gematik.idp.token.JsonWebToken;
import java.net.ConnectException;
import java.net.NoRouteToHostException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.net.http.HttpConnectTimeoutException;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertificateException;
import java.util.Optional;
import java.util.Queue;
import java.util.Set;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import kong.unirest.core.HttpResponse;
import kong.unirest.core.Unirest;
import kong.unirest.core.UnirestException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;

@Slf4j
public abstract class HttpClient {

  public static Optional<JsonWebToken> fetchSignedJwks(final String signedJwksUri) {
    try {
      final HttpResponse<String> resp = Unirest.get(signedJwksUri).asString();
      if (resp.isSuccess()) {
        // TODO check signature
        return Optional.of(new JsonWebToken(resp.getBody()));
      }
      return Optional.empty();
    } catch (final UnirestException e) {
      throw mapToGsiException("signed JWKS URI", signedJwksUri, e);
    }
  }

  public static RpToken fetchEntityStatementRp(final String issuer) {
    final String entityStatementUrl = issuer + IdpConstants.ENTITY_STATEMENT_ENDPOINT;
    try {
      final HttpResponse<String> resp = Unirest.get(entityStatementUrl).asString();
      if (resp.getStatus() == HttpStatus.OK.value()) {
        return new RpToken(new JsonWebToken(resp.getBody()));
      } else {
        log.info(resp.getBody());
        throw new GsiException(
            INVALID_REQUEST,
            "No entity statement of  ["
                + issuer
                + "] available. Reason: "
                + resp.getBody()
                + HttpStatus.valueOf(resp.getStatus()),
            HttpStatus.BAD_REQUEST);
      }
    } catch (final UnirestException e) {
      throw mapToGsiException("entity statement", entityStatementUrl, e);
    }
  }

  public static JsonWebToken fetchEntityStatementAboutRp(
      final String sub, final String fedmasterUrl, final String entityStmntEndpoint) {
    log.info("FedmasterUrl: " + fedmasterUrl);
    try {
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
    } catch (final UnirestException e) {
      throw mapToGsiException("federation fetch endpoint", entityStmntEndpoint, e);
    }
  }

  public static void sendLogsToBde(
      final Queue<String> logs, final String filename, final String bdeEndpointUrl) {
    Unirest.config().verifySsl(false);
    final String logString = String.join("\n", logs);
    final HttpResponse<String> resp =
        Unirest.post(bdeEndpointUrl)
            .header("Content-Type", "application/octet-stream")
            .header("Accept-Encoding", "gzip, deflate")
            .header("filename", filename)
            .body(logString.isEmpty() ? "leer" : logString)
            .asString();
    log.info("BDE response; status: " + resp.getStatus() + "; body: " + resp.getBody());
  }

  private static boolean isSSLException(final UnirestException e) {
    return isAnyCauseOfExceptionInSet(e, SSL_EXCEPTIONS);
  }

  private static boolean isConnectionException(final UnirestException e) {
    return isAnyCauseOfExceptionInSet(e, CONNECTION_EXCEPTIONS);
  }

  private static boolean isAnyCauseOfExceptionInSet(
      final UnirestException e, final Set<Class<? extends Throwable>> exceptions) {
    Throwable cause = e.getCause();
    while (cause != null) {
      for (final Class<? extends Throwable> exceptionClass : exceptions) {
        if (exceptionClass.isInstance(cause)) {
          return true;
        }
      }
      cause = cause.getCause();
    }
    return false;
  }

  private static GsiException mapToGsiException(
      final String targetDescription, final String targetUrl, final UnirestException e) {
    if (isSSLException(e)) {
      log.info("SSL exception for {} at [{}]", targetDescription, targetUrl, e);
      return new GsiException(
          "SSL certificate validation failed for [" + targetUrl + "]. Reason: " + e.getMessage(),
          e,
          HttpStatus.BAD_REQUEST,
          INVALID_REQUEST);
    }
    if (isConnectionException(e)) {
      log.error("Could not reach {} at [{}]", targetDescription, targetUrl, e);
      return new GsiException(
          "Could not reach "
              + targetDescription
              + " at ["
              + targetUrl
              + "]. Reason: "
              + e.getMessage(),
          e,
          HttpStatus.BAD_GATEWAY,
          INVALID_REQUEST);
    }
    log.error("UnirestException while fetching {} at [{}]", targetDescription, targetUrl, e);
    return new GsiException(
        INVALID_REQUEST,
        "Error when fetching "
            + targetDescription
            + " at ["
            + targetUrl
            + "]. Reason: "
            + e.getMessage(),
        HttpStatus.BAD_REQUEST);
  }

  private static final Set<Class<? extends Throwable>> SSL_EXCEPTIONS =
      Set.of(
          SSLHandshakeException.class,
          SSLException.class,
          CertPathBuilderException.class,
          CertificateException.class);

  private static final Set<Class<? extends Throwable>> CONNECTION_EXCEPTIONS =
      Set.of(
          HttpConnectTimeoutException.class,
          SocketTimeoutException.class,
          ConnectException.class,
          UnknownHostException.class,
          NoRouteToHostException.class);
}
