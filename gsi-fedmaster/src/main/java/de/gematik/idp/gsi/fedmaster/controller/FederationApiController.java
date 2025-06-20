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

package de.gematik.idp.gsi.fedmaster.controller;

import static de.gematik.idp.IdpConstants.ENTITY_STATEMENT_TYP;
import static de.gematik.idp.gsi.fedmaster.Constants.FEDMASTER_FEDERATION_FETCH_ENDPOINT;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.data.JwtHelper;
import de.gematik.idp.gsi.fedmaster.exceptions.FedmasterException;
import de.gematik.idp.gsi.fedmaster.services.EntityStatementFederationMemberBuilder;
import de.gematik.idp.gsi.fedmaster.services.ServerUrlService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.constraints.NotEmpty;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@Slf4j
public class FederationApiController {

  private final EntityStatementFederationMemberBuilder entityStatementFederationMemberBuilder;
  private final ServerUrlService serverUrlService;
  private final IdpJwtProcessor jwtProcessor;
  private final ObjectMapper objectMapper;

  @GetMapping(
      value = FEDMASTER_FEDERATION_FETCH_ENDPOINT,
      produces = "application/entity-statement+jwt;charset=UTF-8")
  public String getEntityStatementFederationMember(
      // iss is a mandatory parameter, but ignored in this scenario
      @RequestParam(name = "iss") @NotEmpty final String iss,
      @RequestParam(name = "sub") @NotEmpty final String sub,
      @RequestParam(name = "aud", required = false) final String aud,
      final HttpServletRequest request) {
    log.debug("RX request to fetch entity statement for federation member {}", sub);
    if (!serverUrlService.determineServerUrl().equals(iss)) {
      log.info(
          " iss [{}] does not match server url [{}]", iss, serverUrlService.determineServerUrl());
      throw new FedmasterException(
          "Issuer entspricht nicht dem Entity Identifier des Federation Masters",
          HttpStatus.BAD_REQUEST,
          "6000");
    }
    return JwtHelper.signJson(
        jwtProcessor,
        objectMapper,
        entityStatementFederationMemberBuilder.buildEntityStatementFederationMember(
            serverUrlService.determineServerUrl(), sub, aud),
        ENTITY_STATEMENT_TYP);
  }
}
