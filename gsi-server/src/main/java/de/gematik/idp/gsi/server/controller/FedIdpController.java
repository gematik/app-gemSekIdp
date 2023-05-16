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

package de.gematik.idp.gsi.server.controller;

import static de.gematik.idp.EnvHelper.getSystemProperty;
import static de.gematik.idp.IdpConstants.ENTITY_STATEMENT_ENDPOINT;
import static de.gematik.idp.IdpConstants.ENTITY_STATEMENT_TYP;
import static de.gematik.idp.IdpConstants.FEDIDP_PAR_AUTH_ENDPOINT;
import static de.gematik.idp.IdpConstants.FED_AUTH_ENDPOINT;
import static de.gematik.idp.IdpConstants.FED_SIGNED_JWKS_ENDPOINT;
import static de.gematik.idp.IdpConstants.TOKEN_ENDPOINT;
import static de.gematik.idp.data.fedidp.Oauth2ErrorCode.INVALID_REQUEST;
import static de.gematik.idp.data.fedidp.Oauth2ErrorCode.INVALID_SCOPE;
import static de.gematik.idp.field.ClaimName.AUTHENTICATION_CLASS_REFERENCE;
import static de.gematik.idp.field.ClaimName.AUTHENTICATION_METHODS_REFERENCE;
import static de.gematik.idp.field.ClaimName.TELEMATIK_GIVEN_NAME;
import static de.gematik.idp.field.ClaimName.TELEMATIK_ID;
import static de.gematik.idp.field.ClaimName.TELEMATIK_ORGANIZATION;
import static de.gematik.idp.field.ClaimName.TELEMATIK_PROFESSION;
import static de.gematik.idp.gsi.server.data.GsiConstants.REQUEST_URI_TTL_SECS;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.gematik.idp.IdpConstants;
import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.crypto.Nonce;
import de.gematik.idp.data.FederationPrivKey;
import de.gematik.idp.data.JwtHelper;
import de.gematik.idp.data.fedidp.ParResponse;
import de.gematik.idp.field.ClientUtilities;
import de.gematik.idp.gsi.server.ServerUrlService;
import de.gematik.idp.gsi.server.data.FedIdpAuthSession;
import de.gematik.idp.gsi.server.data.GsiConstants;
import de.gematik.idp.gsi.server.data.TokenResponse;
import de.gematik.idp.gsi.server.exceptions.GsiException;
import de.gematik.idp.gsi.server.services.AuthenticationService;
import de.gematik.idp.gsi.server.services.EntityStatementBuilder;
import de.gematik.idp.gsi.server.services.EntityStatementRpService;
import de.gematik.idp.gsi.server.services.SektoralIdpAuthenticator;
import de.gematik.idp.gsi.server.token.IdTokenBuilder;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.client.utils.URIBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@Validated
@RestController
@RequiredArgsConstructor
@Slf4j
public class FedIdpController {

  public static final int URI_NONCE_LENGTH = 16;
  public static final int AUTH_CODE_LENGTH = 16;
  private static final int MAX_AUTH_SESSION_AMOUNT = 10000;

  private final EntityStatementRpService entityStatementRpService;
  private final EntityStatementBuilder entityStatementBuilder;
  private final SektoralIdpAuthenticator sektoralIdpAuthenticator;
  private final AuthenticationService authenticationService;
  private final ServerUrlService serverUrlService;
  private final IdpJwtProcessor jwtProcessorSigKey;
  private final IdpJwtProcessor jwtProcessorTokenKey;
  private final ObjectMapper objectMapper;

  @Autowired FederationPrivKey entityStatementSigKey;

  // TODO: delete oldest entry
  private final List<FedIdpAuthSession> fedIdpAuthSessions = new ArrayList<>();

  private static void setNoCacheHeader(final HttpServletResponse response) {
    response.setHeader("Cache-Control", "no-store");
    response.setHeader("Pragma", "no-cache");
  }

  @GetMapping(
      value = ENTITY_STATEMENT_ENDPOINT,
      produces = "application/entity-statement+jwt;charset=UTF-8")
  public String getEntityStatement() {
    return JwtHelper.signJson(
        jwtProcessorSigKey,
        objectMapper,
        entityStatementBuilder.buildEntityStatement(serverUrlService.determineServerUrl()),
        ENTITY_STATEMENT_TYP);
  }

  @GetMapping(value = FED_SIGNED_JWKS_ENDPOINT, produces = "application/jose;charset=UTF-8")
  public String getSignedJwks() {
    return JwtHelper.signJson(
        jwtProcessorSigKey, objectMapper, JwtHelper.getJwks(entityStatementSigKey), "jwk-set+json");
  }

  /* Federation App2App flow
   * Request(in)  == message nr.2 PushedAuthRequest(PAR)
   *                 messages nr.2c ... nr.2d
   * Response(out)== message nr.3
   * Parameter "params" is used to filter by HTTP parameters and let spring decide which (multiple mappings of same endpoint) mapping matches.
   */
  @PostMapping(
      value = FEDIDP_PAR_AUTH_ENDPOINT,
      params = "acr_values",
      produces = "application/json;charset=UTF-8",
      consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
  public ParResponse postPar(
      @RequestParam(name = "client_id") @NotEmpty @Pattern(regexp = "^https?://.*$")
          final String fachdienstClientId,
      @RequestParam(name = "state") @NotEmpty final String fachdienstState,
      @RequestParam(name = "redirect_uri") @NotEmpty String fachdienstRedirectUri,
      @RequestParam(name = "code_challenge") @NotEmpty final String fachdienstCodeChallenge,
      @RequestParam(name = "code_challenge_method") @NotEmpty @Pattern(regexp = "S256")
          final String fachdienstCodeChallengeMethod,
      @RequestParam(name = "response_type") @NotEmpty @Pattern(regexp = "code")
          final String responseType,
      @RequestParam(name = "nonce") @NotEmpty final String fachdienstNonce,
      @RequestParam(name = "scope") @NotEmpty final String scope,
      @RequestParam(name = "acr_values")
          @NotEmpty
          @Pattern(regexp = "gematik-ehealth-loa-high|gematik-ehealth-loa-substantial")
          final String acrValues,
      final HttpServletResponse respMsgNr3) {
    log.info(
        "App2App-Flow: RX message nr 2 (Pushed Authorization Request) received at {}",
        serverUrlService.determineServerUrl());

    entityStatementRpService.doAutoregistration(fachdienstClientId, fachdienstRedirectUri);

    log.info("Amount of stored fedIdpAuthSessions: {}", fedIdpAuthSessions.size());

    // from specification: "URI zur späteren Identifikation des Requestes":
    // https://tools.ietf.org/id/draft-ietf-oauth-par-04.html#section-2.2
    final String requestUri =
        "urn:" + fachdienstClientId + ":" + Nonce.getNonceAsHex(URI_NONCE_LENGTH);

    if (getSystemProperty("LTU_DEV").isPresent()) {
      log.info("\"LTU_DEV\" as system property detected, overwrite fachdienstRedirectUri");
      fachdienstRedirectUri = "https://idpfadi.dev.gematik.solutions";
    }

    fedIdpAuthSessions.add(
        FedIdpAuthSession.builder()
            .fachdienstClientId(fachdienstClientId)
            .fachdienstState(fachdienstState)
            .fachdienstCodeChallenge(fachdienstCodeChallenge)
            .fachdienstCodeChallengeMethod(fachdienstCodeChallengeMethod)
            .fachdienstNonce(fachdienstNonce)
            .requestedScopes(getRequestedScopes(scope))
            .fachdienstRedirectUri(fachdienstRedirectUri)
            .authorizationCode(Nonce.getNonceAsHex(AUTH_CODE_LENGTH))
            .requestUri(requestUri)
            .expiresAt(ZonedDateTime.now().plusSeconds(REQUEST_URI_TTL_SECS).toString())
            .build());

    log.info(
        "Stored FedIdpAuthSession:\n {}", fedIdpAuthSessions.get(fedIdpAuthSessions.size() - 1));

    setNoCacheHeader(respMsgNr3);
    respMsgNr3.setStatus(HttpStatus.CREATED.value());

    return ParResponse.builder().requestUri(requestUri).expiresIn(REQUEST_URI_TTL_SECS).build();
  }

  private Set<String> getRequestedScopes(@NotNull final String scope) {
    final Set<String> requestedScopes = Arrays.stream(scope.split(" ")).collect(Collectors.toSet());

    if (!(GsiConstants.SCOPES_SUPPORTED.containsAll(requestedScopes))) {
      throw new GsiException(INVALID_SCOPE, "Requested scopes do no fit.", HttpStatus.BAD_REQUEST);
    }
    return requestedScopes;
  }

  /* Federation App2App/Web2App flow
   * Request(in)  == message nr.6 request_uri, client_id
   * Response(out)== landing page
   */

  @GetMapping(value = FED_AUTH_ENDPOINT, produces = MediaType.TEXT_HTML_VALUE)
  @ResponseBody
  public void getLandingPage(
      @RequestParam(name = "request_uri") @NotEmpty final String requestUri,
      @RequestParam(name = "client_id") @NotEmpty final String clientId,
      final HttpServletResponse resp)
      throws URISyntaxException {

    log.info(
        "App2App-Flow: RX message nr 6 (Authorization Request) at {}",
        serverUrlService.determineServerUrl());
    final int sessionIdx = getSessionIndex(URLDecoder.decode(requestUri, StandardCharsets.UTF_8));
    final FedIdpAuthSession session = fedIdpAuthSessions.get(sessionIdx);
    verifyClientId(clientId, session.getFachdienstClientId());

    setNoCacheHeader(resp);
    resp.setStatus(HttpStatus.FOUND.value());

    final URIBuilder redirectUriBuilder =
        new URIBuilder(serverUrlService.determineServerUrl() + "/landing.html");
    final String location = redirectUriBuilder.build().toString();
    resp.setHeader(HttpHeaders.LOCATION, location);
  }

  @GetMapping(
      value = FED_AUTH_ENDPOINT,
      params = {"user_id"})
  public void authorizationCode_userConsent(
      @RequestParam(name = "request_uri") @NotEmpty final String requestUri,
      @RequestParam(name = "user_id") @NotEmpty final String userId,
      final HttpServletResponse respMsgNr7) {
    log.info(
        "App2App-Flow: RX message nr 6b (user consent) at {}",
        serverUrlService.determineServerUrl());
    final int sessionIdx = getSessionIndex(URLDecoder.decode(requestUri, StandardCharsets.UTF_8));
    final FedIdpAuthSession session = fedIdpAuthSessions.get(sessionIdx);

    // bind user to session
    authenticationService.doAuthentication(session.getUserData(), userId);

    setNoCacheHeader(respMsgNr7);
    respMsgNr7.setStatus(HttpStatus.FOUND.value());

    final String tokenLocation =
        sektoralIdpAuthenticator.createLocationForAuthorizationResponse(
            session.getFachdienstRedirectUri(),
            session.getFachdienstState(),
            session.getAuthorizationCode());

    respMsgNr7.setHeader(HttpHeaders.LOCATION, tokenLocation);
  }

  /* Federation App2App flow
   * Request(in)  == message nr.10 AUTH_CODE
   * Response(out)== message nr.11 ID_TOKEN (ACCESS_TOKEN)
   */
  @PostMapping(
      value = TOKEN_ENDPOINT,
      params = {"code"},
      consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
  public TokenResponse getTokensForCode(
      @RequestParam("grant_type") @NotEmpty @Pattern(regexp = "authorization_code")
          final String grantType,
      @RequestParam("code") @NotEmpty final String code,
      @RequestParam("code_verifier") @NotEmpty final String codeVerifier,
      @RequestParam("client_id") @NotEmpty final String clientId,
      @RequestParam("redirect_uri") @NotEmpty final String redirectUri,
      final HttpServletResponse respMsgNr11) {
    log.info(
        "App2App-Flow: RX message nr 10 (Authorization Code) at {}",
        serverUrlService.determineServerUrl());
    final int sessionIdx = getSessionIndexAuthCode(URLDecoder.decode(code, StandardCharsets.UTF_8));
    final FedIdpAuthSession session = fedIdpAuthSessions.get(sessionIdx);
    verifyRedirectUri(redirectUri, session.getFachdienstRedirectUri());
    verifyCodeVerifier(codeVerifier, session.getFachdienstCodeChallenge());
    verifyClientId(clientId, session.getFachdienstClientId());

    setNoCacheHeader(respMsgNr11);
    respMsgNr11.setStatus(HttpStatus.OK.value());

    final IdTokenBuilder idTokenBuilder =
        new IdTokenBuilder(jwtProcessorTokenKey, serverUrlService.determineServerUrl());
    final String idToken =
        idTokenBuilder
            .buildIdToken(clientId, getUserDataClaims(), session.getFachdienstNonce())
            .getRawString();
    return TokenResponse.builder()
        .idToken(idToken)
        .accessToken("TODO ACCESS_TOKEN")
        .tokenType("Bearer")
        .expiresIn(300)
        .build();
  }

  private static void verifyRedirectUri(final String redirectUri, final String sessionRedirectUri) {
    if (!redirectUri.equals(sessionRedirectUri)) {
      throw new GsiException(INVALID_REQUEST, "invalid redirect_uri", HttpStatus.BAD_REQUEST);
    }
  }

  private static void verifyCodeVerifier(final String codeVerifier, final String codeChallenge) {
    if (!ClientUtilities.generateCodeChallenge(codeVerifier).equals(codeChallenge)) {
      throw new GsiException(INVALID_REQUEST, "invalid code_verifier", HttpStatus.BAD_REQUEST);
    }
  }

  private static void verifyClientId(final String clientId, final String sessionClientId) {
    if (!sessionClientId.equals(clientId)) {
      throw new GsiException(INVALID_REQUEST, "invalid client_id", HttpStatus.BAD_REQUEST);
    }
  }

  private Map<String, Object> getUserDataClaims() {
    // TODO: claims depend on other data -> refactor
    return Map.ofEntries(
        Map.entry(TELEMATIK_GIVEN_NAME.getJoseName(), "Jules Winnfield"),
        Map.entry(TELEMATIK_ID.getJoseName(), "230847"),
        Map.entry(TELEMATIK_ORGANIZATION.getJoseName(), "Heartbreakers"),
        Map.entry(TELEMATIK_PROFESSION.getJoseName(), "Patient"),
        Map.entry(AUTHENTICATION_CLASS_REFERENCE.getJoseName(), IdpConstants.EIDAS_LOA_HIGH),
        Map.entry(AUTHENTICATION_METHODS_REFERENCE.getJoseName(), "urn:telematik:auth:eID"));
  }

  private int getSessionIndex(final String requestUri) {
    return fedIdpAuthSessions.stream()
        .filter(entry -> entry.getRequestUri().equals(requestUri))
        .map(fedIdpAuthSessions::indexOf)
        .findAny()
        .orElseThrow(
            () -> new GsiException(INVALID_REQUEST, "invalid request_uri", HttpStatus.BAD_REQUEST));
  }

  private int getSessionIndexAuthCode(final String authorizationCode) {
    return fedIdpAuthSessions.stream()
        .filter(entry -> entry.getAuthorizationCode().equals(authorizationCode))
        .map(fedIdpAuthSessions::indexOf)
        .findAny()
        .orElseThrow(
            () -> new GsiException(INVALID_REQUEST, "invalid code", HttpStatus.BAD_REQUEST));
  }
}
