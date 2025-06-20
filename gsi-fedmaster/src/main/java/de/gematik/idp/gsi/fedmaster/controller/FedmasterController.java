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

import static de.gematik.idp.IdpConstants.ENTITY_STATEMENT_ENDPOINT;
import static de.gematik.idp.IdpConstants.ENTITY_STATEMENT_TYP;
import static de.gematik.idp.IdpConstants.IDP_LIST_ENDPOINT;
import static de.gematik.idp.gsi.fedmaster.Constants.FED_LIST_ENDPOINT;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.data.JwtHelper;
import de.gematik.idp.gsi.fedmaster.services.EntityStatementBuilder;
import de.gematik.idp.gsi.fedmaster.services.FedListBuilder;
import de.gematik.idp.gsi.fedmaster.services.IdpListBuilder;
import de.gematik.idp.gsi.fedmaster.services.ServerUrlService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@Slf4j
public class FedmasterController {

  private final EntityStatementBuilder entityStatementBuilder;
  private final IdpListBuilder idpListBuilder;
  private final FedListBuilder fedListBuilder;
  private final ServerUrlService serverUrlService;
  private final IdpJwtProcessor jwtProcessor;
  private final ObjectMapper objectMapper;

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

  @GetMapping(value = IDP_LIST_ENDPOINT, produces = "application/jwt;charset=UTF-8")
  public String getEntityListing() {
    return JwtHelper.signJson(
        jwtProcessor,
        objectMapper,
        idpListBuilder.buildIdpList(serverUrlService.determineServerUrl()),
        "idp-list+jwt");
  }

  @GetMapping(value = FED_LIST_ENDPOINT, produces = "application/json;charset=UTF-8")
  public String getFederationList() {
    return fedListBuilder.buildFedList().toString();
  }
}
