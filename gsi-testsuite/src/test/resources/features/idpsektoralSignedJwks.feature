#
# Copyright 2023 gematik GmbH
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

@SignedJwks
@PRODUKT:IDP-Sek
Feature: Test signed Jwks of IdpSektoral

  Background: Initialisiere Testkontext durch Abfrage des Entity Statements
    When TGR sende eine leere GET Anfrage an "${gsi.fachdienstEntityStatementEndpoint}"
    And TGR find request to path ".*/.well-known/openid-federation"
    And Expect JWKS in last message and add its keys to truststore
    Then TGR set local variable "signed_jwks_uri" to "!{rbel:currentResponseAsString('$..signed_jwks_uri')}"
    And TGR set local variable "entity_statement_sig_kid" to "!{rbel:currentResponseAsString('$.body.header.kid')}"


  @TCID:IDPSEKTORAL_SIGNED_JWKS_001
  @Approval
  @PRIO:1
  @TESTSTUFE:4
  Scenario: IdpSektoral signedJwks - Gutfall - Validiere Response

  ```
  Wir rufen das signed jwks beim IdpSektoral ab

  Die HTTP Response muss:

  - den Code 200
  - einen JWS enthalten

    Given TGR clear recorded messages
    And Send Get Request to "${signed_jwks_uri}"
    And TGR find request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "200"
    And TGR current response with attribute "$.header.Content-Type" matches "application/jwk-set.*"


  @TCID:IDPSEKTORAL_SIGNED_JWKS_002
  @Approval
  @PRIO:1
  @TESTSTUFE:4
  Scenario: IdpSektoral signedJwks - Gutfall - Validiere Response Header Claims

  ```
  Wir rufen das signed jwks beim IdpSektoral ab

  Der Response Body muss ein JWS mit den folgenden Header Claims sein:

    Given TGR clear recorded messages
    And Send Get Request to "${signed_jwks_uri}"
    And TGR find request to path ".*"
    Then TGR current response at "$.body.header" matches as JSON:
            """
          {
          alg:        'ES256',
          kid:        '.*',
          typ:        'jwk-set+json'
          }
        """

  @TCID:IDPSEKTORAL_SIGNED_JWKS_003
  @Approval
  @PRIO:1
  @TESTSTUFE:4
  Scenario: IdpSektoral signedJwks - Gutfall - Validiere Response Body Claims

  ```
  Wir rufen das signed jwks beim IdpSektoral ab

  Der Response Body muss ein JWS mit den korrekten Body Claims sein:

    Given TGR clear recorded messages
    And Send Get Request to "${signed_jwks_uri}"
    And TGR find request to path ".*"
    Then TGR current response at "$.body.body" matches as JSON:
    """
      {
        iss:                           '.*',
        iat:                           "${json-unit.ignore}",
        keys:                          "${json-unit.ignore}"
      }
    """
    Then TGR current response at "$.body.body.keys.0" matches as JSON:
        """
          {
            use:                           'sig',
            kid:                           '.*',
            kty:                           'EC',
            crv:                           'P-256',
            x:                             "${json-unit.ignore}",
            y:                             "${json-unit.ignore}",
          }
        """