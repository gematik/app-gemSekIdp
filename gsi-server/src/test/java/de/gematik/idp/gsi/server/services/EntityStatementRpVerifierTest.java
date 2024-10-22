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

import static de.gematik.idp.gsi.server.common.Constants.ENTITY_STMNT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2043;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.gematik.idp.gsi.server.exceptions.GsiException;
import de.gematik.idp.token.JsonWebToken;
import org.junit.jupiter.api.Test;

class EntityStatementRpVerifierTest {

  private static final JsonWebToken VALID_ENTITY_STMNT =
      new JsonWebToken(ENTITY_STMNT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2043);

  @Test
  void test_verifyRedirectUriExistsInEntityStmnt_VALID() {
    assertDoesNotThrow(
        () ->
            EntityStatementRpVerifier.verifyRedirectUriExistsInEntityStmnt(
                VALID_ENTITY_STMNT, "https://Fachdienst007.de/client"));
  }

  @Test
  void test_verifyRedirectUriExistsInEntityStmnt_throwsException_INVALID() {
    final String invalidRedirectUri = "https://uri-does-not-exist-in-entity-stmnt";
    assertThatThrownBy(
            () ->
                EntityStatementRpVerifier.verifyRedirectUriExistsInEntityStmnt(
                    VALID_ENTITY_STMNT, invalidRedirectUri))
        .isInstanceOf(GsiException.class)
        .hasMessageContaining(
            "Content of parameter redirect_uri ["
                + invalidRedirectUri
                + "] not found in entity statement. ");
  }

  @Test
  void test_verifyRequestedScopesListedInEntityStmnt_VALID() {
    assertDoesNotThrow(
        () ->
            EntityStatementRpVerifier.verifyRequestedScopesListedInEntityStmnt(
                VALID_ENTITY_STMNT,
                "urn:telematik:display_name urn:telematik:versicherter openid"));
  }

  @Test
  void test_verifyRequestedScopesListedInEntityStmnt_throwsException_INVALID() {
    final String invalidScopes = "urn:telematik:display_name urn:telematik:alter openid";
    assertThatThrownBy(
            () ->
                EntityStatementRpVerifier.verifyRequestedScopesListedInEntityStmnt(
                    VALID_ENTITY_STMNT, "urn:telematik:display_name urn:telematik:alter openid"))
        .isInstanceOf(GsiException.class)
        .hasMessageContaining(
            "Content of parameter scope ["
                + invalidScopes
                + "] exceeds scopes found in entity statement. ");
  }
}
