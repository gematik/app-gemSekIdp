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

package de.gematik.idp.gsi.server.controller;

import static de.gematik.idp.IdpConstants.ENTITY_STATEMENT_ENDPOINT;
import static de.gematik.idp.IdpConstants.ENTITY_STATEMENT_TYP;
import static de.gematik.idp.IdpConstants.FED_AUTH_ENDPOINT;
import static de.gematik.idp.IdpConstants.TOKEN_ENDPOINT;
import static de.gematik.idp.data.Oauth2ErrorCode.INVALID_REQUEST;
import static de.gematik.idp.gsi.server.data.GsiConstants.FEDIDP_PAR_AUTH_ENDPOINT;
import static de.gematik.idp.gsi.server.data.GsiConstants.FED_SIGNED_JWKS_ENDPOINT;
import static de.gematik.idp.gsi.server.data.GsiConstants.REQUEST_URI_TTL_SECS;
import static de.gematik.idp.gsi.server.util.ClaimHelper.getClaimsForScopeSet;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.crypto.Nonce;
import de.gematik.idp.data.FederationPrivKey;
import de.gematik.idp.data.JwtHelper;
import de.gematik.idp.data.ParResponse;
import de.gematik.idp.data.TokenResponse;
import de.gematik.idp.field.ClientUtilities;
import de.gematik.idp.gsi.server.configuration.GsiConfiguration;
import de.gematik.idp.gsi.server.data.ClaimsResponse;
import de.gematik.idp.gsi.server.data.FedIdpAuthSession;
import de.gematik.idp.gsi.server.data.QRCodeGenerator;
import de.gematik.idp.gsi.server.exceptions.GsiException;
import de.gematik.idp.gsi.server.services.AuthenticationService;
import de.gematik.idp.gsi.server.services.EntityStatementBuilder;
import de.gematik.idp.gsi.server.services.EntityStatementRpService;
import de.gematik.idp.gsi.server.services.JwksBuilder;
import de.gematik.idp.gsi.server.services.SektoralIdpAuthenticator;
import de.gematik.idp.gsi.server.services.ServerUrlService;
import de.gematik.idp.gsi.server.token.IdTokenBuilder;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import java.io.Serial;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jose4j.lang.JoseException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

@Validated
@Controller
@RequiredArgsConstructor
@Slf4j
public class FedIdpController {

  public static final int URI_NONCE_LENGTH = 16;
  public static final int AUTH_CODE_LENGTH = 16;
  private static final int MAX_AUTH_SESSION_AMOUNT = 10000;
  public static final int ID_TOKEN_TTL_SECONDS = 300;

  private final EntityStatementRpService entityStatementRpService;
  private final EntityStatementBuilder entityStatementBuilder;
  private final SektoralIdpAuthenticator sektoralIdpAuthenticator;
  private final AuthenticationService authenticationService;
  private final ServerUrlService serverUrlService;
  private final IdpJwtProcessor jwtProcessorEsSigPrivKey;
  private final IdpJwtProcessor jwtProcessorTokenSigPrivKey;
  private final ObjectMapper objectMapper;
  private final GsiConfiguration gsiConfiguration;
  private final JwksBuilder jwksBuilder;

  @Autowired FederationPrivKey esSigPrivKey;
  @Autowired FederationPrivKey tokenSigPrivKey;

  private final Map<String, FedIdpAuthSession> fedIdpAuthSessions =
      Collections.synchronizedMap(
          new LinkedHashMap<>() {
            @Serial private static final long serialVersionUID = -800086030628953996L;

            @Override
            protected boolean removeEldestEntry(final Entry<String, FedIdpAuthSession> eldest) {
              return size() > MAX_AUTH_SESSION_AMOUNT;
            }
          });

  private static void setNoCacheHeader(final HttpServletResponse response) {
    response.setHeader("Cache-Control", "no-store");
    response.setHeader("Pragma", "no-cache");
  }

  @ResponseBody
  @GetMapping(
      value = ENTITY_STATEMENT_ENDPOINT,
      produces = "application/entity-statement+jwt;charset=UTF-8")
  public String getEntityStatement() {
    return JwtHelper.signJson(
        jwtProcessorEsSigPrivKey,
        objectMapper,
        entityStatementBuilder.buildEntityStatement(
            serverUrlService.determineServerUrl(), gsiConfiguration.getFedmasterUrl()),
        ENTITY_STATEMENT_TYP);
  }

  @ResponseBody
  @GetMapping(value = FED_SIGNED_JWKS_ENDPOINT, produces = "application/jwk-set+json;charset=UTF-8")
  public String getSignedJwks() {
    return JwtHelper.signJson(
        jwtProcessorEsSigPrivKey,
        objectMapper,
        jwksBuilder.build(serverUrlService.determineServerUrl()),
        "jwk-set+json");
  }

  /* Federation App2App flow
   * Request(in)  == message nr.2 PushedAuthRequest(PAR)
   *                 messages nr.2c ... nr.2d
   * Response(out)== message nr.3
   * Parameter "params" is used to filter by HTTP parameters and let spring decide which (multiple mappings of same endpoint) mapping matches.
   */
  @ResponseBody
  @PostMapping(
      value = FEDIDP_PAR_AUTH_ENDPOINT,
      params = "acr_values",
      produces = "application/json;charset=UTF-8",
      consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
  public ParResponse postPar(
      @RequestParam(name = "client_id") @NotEmpty @Pattern(regexp = "^https?://.*$")
          final String fachdienstClientId,
      @RequestParam(name = "state") @NotEmpty final String fachdienstState,
      @RequestParam(name = "redirect_uri") @NotEmpty final String fachdienstRedirectUri,
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

    entityStatementRpService.doAutoregistration(fachdienstClientId, fachdienstRedirectUri, scope);

    log.info("Amount of stored fedIdpAuthSessions: {}", fedIdpAuthSessions.size());

    // from specification: "URI zur späteren Identifikation des Requestes":
    // https://tools.ietf.org/id/draft-ietf-oauth-par-04.html#section-2.2
    final String requestUri =
        "urn:" + fachdienstClientId + ":" + Nonce.getNonceAsHex(URI_NONCE_LENGTH);

    fedIdpAuthSessions.put(
        requestUri,
        FedIdpAuthSession.builder()
            .fachdienstClientId(fachdienstClientId)
            .fachdienstState(fachdienstState)
            .fachdienstCodeChallenge(fachdienstCodeChallenge)
            .fachdienstCodeChallengeMethod(fachdienstCodeChallengeMethod)
            .fachdienstNonce(fachdienstNonce)
            .requestedScopes(Arrays.stream(scope.split(" ")).collect(Collectors.toSet()))
            .fachdienstRedirectUri(fachdienstRedirectUri)
            .authorizationCode(Nonce.getNonceAsHex(AUTH_CODE_LENGTH))
            .expiresAt(ZonedDateTime.now().plusSeconds(REQUEST_URI_TTL_SECS).toString())
            .build());

    log.info(
        "Stored FedIdpAuthSession under requestUri {}:\n {}",
        requestUri,
        fedIdpAuthSessions.get(requestUri));

    setNoCacheHeader(respMsgNr3);
    respMsgNr3.setStatus(HttpStatus.CREATED.value());

    return ParResponse.builder().requestUri(requestUri).expiresIn(REQUEST_URI_TTL_SECS).build();
  }

  /* Federation App2App/Web2App flow
   * Request(in)  == message nr.6 request_uri, client_id
   * Response(out)== landing page, with submit button: will send messages 6b/6d in one piece
   */
  @GetMapping(
      value = FED_AUTH_ENDPOINT,
      params = {"request_uri", "client_id"})
  public String getLandingPage(
      @RequestParam(name = "request_uri") @NotEmpty final String requestUri,
      @RequestParam(name = "client_id") @NotEmpty final String clientId,
      final Model model) {
    final String thisEndpointUrl = serverUrlService.determineServerUrl() + FED_AUTH_ENDPOINT;
    log.info("App2App-Flow: RX message nr 6 (Authorization Request) at {}", thisEndpointUrl);
    validateAuthRequestParams(requestUri, clientId);
    log.info("request_uri: {}, client_id: {}", requestUri, clientId);

    model.addAttribute("requestUri", requestUri);
    model.addAttribute("clientId", clientId);
    model.addAttribute("fedAuthEndpointUrl", thisEndpointUrl);
    final String dataUri = QRCodeGenerator.generate("https://tbd/tbd?tbd=tbd&tbd=tbd");
    model.addAttribute("dynamicImageDataUri", dataUri);
    return "landingTemplate";
  }

  @ResponseBody
  @GetMapping(
      value = FED_AUTH_ENDPOINT,
      params = {"device_type"})
  public ClaimsResponse getRequestedClaims(
      @RequestParam(name = "request_uri") @NotEmpty final String requestUri,
      @RequestParam(name = "device_type") @NotEmpty final String deviceType,
      final HttpServletResponse respMsgNr6a) {
    final String thisEndpointUrl = serverUrlService.determineServerUrl() + FED_AUTH_ENDPOINT;
    log.info(
        "App2App-Flow: RX message nr 6 (Authorization Request, getRequetedClaims) at {}",
        thisEndpointUrl);

    final FedIdpAuthSession session = getSessionByRequestUri(requestUri);
    final Set<String> requestedScopes = session.getRequestedScopes();
    final Set<String> requestedClaims = getClaimsForScopeSet(requestedScopes);
    respMsgNr6a.setStatus(HttpStatus.OK.value());
    return ClaimsResponse.builder().requestedClaims(requestedClaims.toArray(new String[0])).build();
  }

  @ResponseBody
  @GetMapping(
      value = FED_AUTH_ENDPOINT,
      params = {"user_id"})
  public void getAuthorizationCode(
      @RequestParam(name = "request_uri") @NotEmpty final String requestUri,
      // user_id as KVNR or fallback
      @RequestParam(name = "user_id") @Pattern(regexp = "^[A-Z]\\d{9}$|^12345678$")
          final String userId,
      @RequestParam(name = "selected_claims", required = false) final String selectedClaims,
      final HttpServletResponse respMsgNr7) {
    log.info(
        "App2App-Flow: RX message nr 6b/6d (user consent) at {}",
        serverUrlService.determineServerUrl());
    final FedIdpAuthSession session = getSessionByRequestUri(requestUri);

    final Set<String> requestedScopes = session.getRequestedScopes();
    final Set<String> requestedClaims = getClaimsForScopeSet(requestedScopes);

    final Set<String> selectedClaimsSet;
    selectedClaimsSet = getSelectedClaimsSet(selectedClaims, requestedClaims);

    // bind user to session (fill user data of session)
    authenticationService.doAuthentication(session.getUserData(), userId, selectedClaimsSet);

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
  @ResponseBody
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

    final String sessionKey =
        getSessionKeyByAuthCode(URLDecoder.decode(code, StandardCharsets.UTF_8));
    final FedIdpAuthSession session = fedIdpAuthSessions.get(sessionKey);

    verifyRedirectUri(redirectUri, session.getFachdienstRedirectUri());
    verifyCodeVerifier(codeVerifier, session.getFachdienstCodeChallenge());
    verifyClientId(clientId, session.getFachdienstClientId());

    setNoCacheHeader(respMsgNr11);
    respMsgNr11.setStatus(HttpStatus.OK.value());

    final String idToken;
    try {
      idToken =
          new IdTokenBuilder(
                  jwtProcessorTokenSigPrivKey,
                  serverUrlService.determineServerUrl(),
                  session.getFachdienstNonce(),
                  clientId,
                  session.getUserData())
              .buildIdToken()
              .encryptAsJwt(entityStatementRpService.getRpEncKey(clientId))
              .getRawString();
    } catch (final JoseException e) {
      throw new GsiException(e);
    }
    // delete session
    fedIdpAuthSessions.remove(sessionKey);

    return TokenResponse.builder()
        .idToken(idToken)
        .accessToken("TODO ACCESS_TOKEN")
        .tokenType("Bearer")
        .expiresIn(ID_TOKEN_TTL_SECONDS)
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

  private FedIdpAuthSession getSessionByRequestUri(final String requestUri) {
    final FedIdpAuthSession session =
        Optional.ofNullable(fedIdpAuthSessions.get(requestUri))
            .orElseThrow(
                () ->
                    new GsiException(
                        INVALID_REQUEST,
                        "unknown request_uri, no session found",
                        HttpStatus.BAD_REQUEST));
    // session found, check if request_uri is expired
    final ZonedDateTime expiredTime =
        ZonedDateTime.parse(session.getExpiresAt(), DateTimeFormatter.ISO_ZONED_DATE_TIME);
    if (ZonedDateTime.now().isAfter(expiredTime)) {
      fedIdpAuthSessions.remove(requestUri);
      throw new GsiException(INVALID_REQUEST, "request_uri expired", HttpStatus.BAD_REQUEST);
    } else {
      return session;
    }
  }

  private String getSessionKeyByAuthCode(final String authorizationCode) {
    return fedIdpAuthSessions.entrySet().stream()
        .filter((entry -> entry.getValue().getAuthorizationCode().equals(authorizationCode)))
        .map(Entry::getKey)
        .findAny()
        .orElseThrow(
            () ->
                new GsiException(
                    INVALID_REQUEST, "unknown code, no session found", HttpStatus.BAD_REQUEST));
  }

  private void validateAuthRequestParams(final String requestUri, final String clientId) {
    final FedIdpAuthSession session = getSessionByRequestUri(requestUri);
    final boolean clientIdBelongsToRequestUri = session.getFachdienstClientId().equals(clientId);
    if (!clientIdBelongsToRequestUri) {
      throw new GsiException(INVALID_REQUEST, "unknown client_id", HttpStatus.BAD_REQUEST);
    }
  }

  private static Set<String> getSelectedClaimsSet(
      final String selectedClaims, final Set<String> requestedClaims) {
    final Set<String> selectedClaimsSet;
    if (selectedClaims == null) {
      selectedClaimsSet = requestedClaims;
    } else {
      selectedClaimsSet = Arrays.stream(selectedClaims.split(" ")).collect(Collectors.toSet());
      if (!new HashSet<>(requestedClaims).containsAll(selectedClaimsSet)) {
        throw new GsiException(
            INVALID_REQUEST, "selected claims exceed scopes in PAR", HttpStatus.BAD_REQUEST);
      }
    }
    return selectedClaimsSet;
  }
}
