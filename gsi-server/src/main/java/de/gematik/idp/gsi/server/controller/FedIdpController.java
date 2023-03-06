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
import static de.gematik.idp.IdpConstants.FED_AUTH_APP_ENDPOINT;
import static de.gematik.idp.IdpConstants.FED_AUTH_ENDPOINT;
import static de.gematik.idp.IdpConstants.TOKEN_ENDPOINT;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.crypto.Nonce;
import de.gematik.idp.data.JwtHelper;
import de.gematik.idp.data.fedidp.ParResponse;
import de.gematik.idp.gsi.server.ServerUrlService;
import de.gematik.idp.gsi.server.data.FedIdpAuthSession;
import de.gematik.idp.gsi.server.data.GsiConstants;
import de.gematik.idp.gsi.server.data.TokenResponse;
import de.gematik.idp.gsi.server.exceptions.GsiException;
import de.gematik.idp.gsi.server.services.EntityStatementBuilder;
import de.gematik.idp.gsi.server.services.SektoralIdpAuthenticator;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@Validated
@RestController
@RequiredArgsConstructor
@Slf4j
public class FedIdpController {

  public static final int URI_NONCE_LENGTH = 16;
  public static final int AUTH_CODE_LENGTH = 16;
  private static final int MAX_AUTH_SESSION_AMOUNT = 10000;
  private final EntityStatementBuilder entityStatementBuilder;
  private final SektoralIdpAuthenticator sektoralIdpAuthenticator;
  private final ServerUrlService serverUrlService;
  private final IdpJwtProcessor jwtProcessor;
  private final ObjectMapper objectMapper;

  private final Map<String, FedIdpAuthSession> fedIdpAuthSessions =
      new LinkedHashMap<>() {

        @Override
        protected boolean removeEldestEntry(final Entry<String, FedIdpAuthSession> eldest) {
          return size() > MAX_AUTH_SESSION_AMOUNT;
        }
      };

  private static void setNoCacheHeader(final HttpServletResponse response) {
    response.setHeader("Cache-Control", "no-store");
    response.setHeader("Pragma", "no-cache");
  }

  @GetMapping(
      value = ENTITY_STATEMENT_ENDPOINT,
      produces = "application/entity-statement+jwt;charset=UTF-8")
  public String getEntityStatement() {
    return JwtHelper.signJson(
        jwtProcessor,
        objectMapper,
        entityStatementBuilder.buildEntityStatement(serverUrlService.determineServerUrl()),
        ENTITY_STATEMENT_TYP);
  }

  /* Federation App2App flow
   * Request(in)  == message nr.2 PushedAuthRequest(PAR)
   *                 messages nr.2c ... nr.2d
   * Response(out)== message nr.3
   * Parameter "params" is used to filter by HTTP parameters and let spring decide which (multiple mappings of same endpoint) mapping matches.
   */
  @PostMapping(
      value = FED_AUTH_ENDPOINT,
      params = "acr_values",
      produces = "application/json;charset=UTF-8",
      consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
  public ParResponse postPar(
      @RequestParam(name = "client_id") @NotEmpty final String fachdienstClientId,
      @RequestParam(name = "state") @NotEmpty final String fachdienstState,
      @RequestParam(name = "redirect_uri") @NotEmpty String fachdienstRedirectUri,
      @RequestParam(name = "code_challenge") @NotEmpty final String fachdienstCodeChallenge,
      @RequestParam(name = "code_challenge_method") @NotEmpty @Pattern(regexp = "S256")
          final String fachdienstCodeChallengeMethod,
      @RequestParam(name = "response_type") @NotEmpty @Pattern(regexp = "code")
          final String responseType,
      @RequestParam(name = "nonce") @NotEmpty final String fachdienstNonce,
      @RequestParam(name = "scope") @NotEmpty final String scope,
      @RequestParam(name = "acr_values") @NotEmpty final String acrValues,
      final HttpServletResponse respMsgNr3) {
    log.info(
        "App2App-Flow: RX message nr 2 (Authorization Request) at {}",
        serverUrlService.determineServerUrl());

    final Set<String> requestedScopes = getRequestedScopes(scope);

    final int REQUEST_URI_TTL_SECS = 90;
    log.info("Amount of stored fedIdpAuthSessions: {}", fedIdpAuthSessions.size());

    // from specification: "URI zur späteren Identifikation des Requestes":
    // https://tools.ietf.org/id/draft-ietf-oauth-par-04.html#section-2.2
    final String requestUri =
        "urn:" + fachdienstClientId + ":" + Nonce.getNonceAsHex(URI_NONCE_LENGTH);

    if (getSystemProperty("LTU_DEV").isPresent()) {
      log.info("\"LTU_DEV\" as system property detected, overwrite fachdienstRedirectUri");
      fachdienstRedirectUri = "https://idpfadi.dev.gematik.solutions";
    }

    fedIdpAuthSessions.put(
        fachdienstState,
        FedIdpAuthSession.builder()
            .fachdienstCodeChallenge(fachdienstCodeChallenge)
            .fachdienstCodeChallengeMethod(fachdienstCodeChallengeMethod)
            .fachdienstNonce(fachdienstNonce)
            .requestedScopes(requestedScopes)
            .fachdienstRedirectUri(fachdienstRedirectUri)
            .authorizationCode(Nonce.getNonceAsHex(AUTH_CODE_LENGTH))
            .requestUri(requestUri)
            .expiresAt(ZonedDateTime.now().plusSeconds(REQUEST_URI_TTL_SECS).toString())
            .build());

    log.info(
        "Stored FedIdpAuthSession:\n key: {}\n value:\n {}",
        fachdienstState,
        fedIdpAuthSessions.get(fachdienstState));

    setNoCacheHeader(respMsgNr3);
    respMsgNr3.setStatus(HttpStatus.CREATED.value());

    return ParResponse.builder().requestUri(requestUri).expiresIn(REQUEST_URI_TTL_SECS).build();
  }

  private Set<String> getRequestedScopes(final String scope) {
    final Set<String> requestedScopes =
        Optional.of(Arrays.stream(scope.split(" ")).collect(Collectors.toSet()))
            .orElseThrow(
                () -> new GsiException("Requested scopes do no fit.", HttpStatus.BAD_REQUEST));

    if (!(requestedScopes.stream().allMatch(GsiConstants.SCOPES_SUPPORTED::contains))) {
      throw new GsiException("Requested scopes do no fit.", HttpStatus.BAD_REQUEST);
    }
    return requestedScopes;
  }

  /* Federation App2App flow
   * Request(in)  == message nr.6 Authorization Request(URI-PAR)
   *                 messages nr.6a ... nr.6b are not implemented
   * Response(out)== message nr.7
   * Parameter "params" is used to filter by HTTP parameters and let spring decide which (multiple mappings of same endpoint) mapping matches.
   */
  @GetMapping(
      value = FED_AUTH_APP_ENDPOINT,
      params = "request_uri",
      produces = "application/json;charset=UTF-8")
  public void getAuthorizationCode(
      @RequestParam(name = "request_uri") @NotEmpty final String requestUri,
      final HttpServletResponse respMsgNr7) {
    log.info(
        "App2App-Flow: RX message nr 6 (Authorization Request) at {}",
        serverUrlService.determineServerUrl());
    final String sessionKey = getSessionKey(URLDecoder.decode(requestUri, StandardCharsets.UTF_8));
    final FedIdpAuthSession session = fedIdpAuthSessions.get(sessionKey);

    setNoCacheHeader(respMsgNr7);
    respMsgNr7.setStatus(HttpStatus.FOUND.value());

    // hard coded authorization code from fasttrack is just reused here
    final String tokenLocation =
        sektoralIdpAuthenticator.createLocationForAuthorizationResponse(
            session.getFachdienstRedirectUri(), sessionKey, session.getAuthorizationCode());
    respMsgNr7.setHeader(HttpHeaders.LOCATION, tokenLocation);
  }

  /* Federation App2App flow
   * Request(in)  == message nr.10 AUTH_CODE
   * Response(out)== message nr.11 ID_TOKEN (ACCESS_TOKEN)
   */
  @PostMapping(
      value = TOKEN_ENDPOINT,
      params = {"client_assertion_type"},
      consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
  public TokenResponse getTokensForCode(
      @RequestParam("grant_type") @NotEmpty @Pattern(regexp = "authorization_code")
          final String grantType,
      @RequestParam("code") @NotEmpty final String code,
      @RequestParam("code_verifier") @NotEmpty final String code_verifier,
      @RequestParam("client_id") @NotEmpty final String clientId,
      @RequestParam("redirect_uri") @NotEmpty final String redirectUri,
      @RequestParam("client_assertion_type") @NotEmpty final String clientAssertionType,
      @RequestParam("client_assertion") @NotEmpty final String clientAssertion,
      final HttpServletResponse respMsgNr11) {
    log.info(
        "App2App-Flow: RX message nr 10 (Authorization Code) at {}",
        serverUrlService.determineServerUrl());
    setNoCacheHeader(respMsgNr11);
    respMsgNr11.setStatus(HttpStatus.OK.value());
    return TokenResponse.builder()
        .idToken("TODO ID_TOKEN")
        .accessToken("TODO ACCESS_TOKEN")
        .tokenType("Bearer")
        .expiresIn(300)
        .build();
  }

  /**
   * @param requestUri the String expected in FedIdpAuthSession
   * @return session key of session which contains the requestUri
   */
  private String getSessionKey(final String requestUri) {
    return fedIdpAuthSessions.entrySet().stream()
        .filter(entry -> entry.getValue().getRequestUri().equals(requestUri))
        .map(Entry::getKey)
        .findAny()
        .orElseThrow();
  }
}
