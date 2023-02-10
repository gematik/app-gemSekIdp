#
# Copyright (c) 2023 gematik GmbH
# 
# Licensed under the Apache License, Version 2.0 (the License);
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

@AuthorizationEndpoint
@GematikSekIdpOnly
Feature: Test IdpSektoral's Auth Endpoint

  Background: Initialisiere Testkontext durch Abfrage des Entity Statements
    Given Fetch Entity statement
    And TGR find request to path "/.well-known/openid-federation"
    Then TGR set local variable "authorization_endpoint" to "!{rbel:currentResponseAsString('$..authorization_endpoint')}"

  @TCID:IDPSEKTORAL_AUTH_ENDPOINT_001
  @Approval
  Scenario: IdpSektoral Auth Endpoint - Gutfall - Validiere Response

  ```
  Wir senden einen PAR an den sektoralen IDP

  Die HTTP Response muss:

  - den Code 200
  - einen json-Body enthalten

    Given TGR clear recorded messages
    When Send Post Request to "${authorization_endpoint}" with
      | client_id    | state       | redirect_uri    | code_challenge                              | code_challenge_method | response_type | nonce                | scope                    | acr_values               |
      | gsi.clientid | yyystateyyy | gsi.redirectUri | 9tI-0CQIkUYaGQOVR1emznlDFjlX0kVY1yd3oiMtGUI | S256                  | code          | vy7rM801AQw1or22GhrZ | profile+telematik+openid | gematik-ehealth-loa-high |
    And TGR find request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "201"
    And TGR current response with attribute "$.header.Content-Type" matches "application/json;charset=UTF-8"


  @TCID:IDPSEKTORAL_AUTH_ENDPOINT_002
  @Approval
  Scenario: IdpSektoral Auth Endpoint - Gutfall - Validiere Response Body

  ```
  Wir senden einen PAR an den sektoralen IDP

  Die Response muss als Body eine korrekte json Struktur enthalten:

    Given TGR clear recorded messages
    When Send Post Request to "${authorization_endpoint}" with
      | client_id    | state       | redirect_uri    | code_challenge                              | code_challenge_method | response_type | nonce                | scope                    | acr_values               |
      | gsi.clientid | yyystateyyy | gsi.redirectUri | 9tI-0CQIkUYaGQOVR1emznlDFjlX0kVY1yd3oiMtGUI | S256                  | code          | vy7rM801AQw1or22GhrZ | profile+telematik+openid | gematik-ehealth-loa-high |
    And TGR find request to path ".*"
    Then TGR current response at "$.body" matches as JSON:
        """
          {
            "request_uri":       '.*',
            "expires_in":        "${json-unit.ignore}"
          }
        """

  @TCID:IDPSEKTORAL_AUTH_ENDPOINT_003
    @OpenBug(GSI-17)
  Scenario Outline: IdpSektoral Auth Endpoint - Negativfall - fehlerhaft befüllte Paramete

  ```
  Wir senden invalide PAR an den sektoralen IDP

  Die Response muss als Body eine passende Fehlermeldung enthalten:

    Given TGR clear recorded messages
    When Send Post Request to "${authorization_endpoint}" with
      | client_id   | state       | redirect_uri   | code_challenge                              | code_challenge_method   | response_type   | nonce                | scope   | acr_values   |
      | <client_id> | yyystateyyy | <redirect_uri> | 9tI-0CQIkUYaGQOVR1emznlDFjlX0kVY1yd3oiMtGUI | <code_challenge_method> | <response_type> | vy7rM801AQw1or22GhrZ | <scope> | <acr_values> |
    And TGR find request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "400"
    And TGR current response at "$.body" matches as JSON:
        """
          {
            "error":                        '.*',
            "____error_description":        '.*'
          }
        """
    And TGR current response at "$.body.error" matches "<error>"


    Examples:
      | client_id    | redirect_uri            | code_challenge_method | response_type | scope                    | acr_values               | error           |
      | notUrl       | gsi.redirectUri         | S256                  | code          | profile+telematik+openid | gematik-ehealth-loa-high | invalid_request |
      | gsi.clientid | gsi.redirectUri         | plain                 | code          | profile+telematik+openid | gematik-ehealth-loa-high | invalid_request |
      | gsi.clientid | gsi.redirectUri         | S256                  | token         | profile+telematik+openid | gematik-ehealth-loa-high | invalid_request |
      | gsi.clientid | gsi.redirectUri         | S256                  | code          | invalidScope             | gematik-ehealth-loa-high | invalid_scope   |
      | gsi.clientid | gsi.redirectUri         | S256                  | code          | profile+telematik+openid | invalidAcr               | invalid_request |
      | gsi.clientid | https://invalidRedirect | S256                  | code          | profile+telematik+openid | gematik-ehealth-loa-high | invalid_request |


  @TCID:IDPSEKTORAL_AUTH_ENDPOINT_004
  @OpenBug(GSI-17)
  Scenario: IdpSektoral Auth Endpoint - Negativfall - falsche HTTP Methode

  ```
  Wir senden invalide PAR an den sektoralen IDP (GET statt POST)

  Die Response muss als Body eine passende Fehlermeldung enthalten:

    Given TGR clear recorded messages
    When Send Get Request to "${authorization_endpoint}" with
      | client_id    | state       | redirect_uri    | code_challenge                              | code_challenge_method | response_type | nonce                | scope                    | acr_values               |
      | gsi.clientid | yyystateyyy | gsi.redirectUri | 9tI-0CQIkUYaGQOVR1emznlDFjlX0kVY1yd3oiMtGUI | S256                  | code          | vy7rM801AQw1or22GhrZ | profile+telematik+openid | gematik-ehealth-loa-high |
    And TGR find request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "405"
    And TGR current response at "$.body" matches as JSON:
        """
          {
            "error":                        'invalid_request',
            "____error_description":        '.*'
          }
        """
    And TGR current response at "$.body.error" matches "invalid_request"
