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

@TokenEndpoint
Feature: Test IdpSektoral's Token Endpoint

  Background: Initialisiere Testkontext durch Abfrage des Entity Statements
    Given Fetch Entity statement
    And TGR find request to path "/.well-known/openid-federation"
    Then TGR set local variable "pushed_authorization_request_endpoint" to "!{rbel:currentResponseAsString('$..pushed_authorization_request_endpoint')}"
    Then TGR set local variable "token_endpoint" to "!{rbel:currentResponseAsString('$..token_endpoint')}"


  @TCID:IDPSEKTORAL_TOKEN_ENDPOINT_003
    @Approval
    @OpenBug
  Scenario Outline: IdpSektoral Token Endpoint - Negativfall - fehlerhaft befüllte Parameter

  ```
  Wir senden einen invalide Token Request an den sektoralen IDP

  Die Response muss als Body eine passende Fehlermeldung enthalten:

    Given TGR clear recorded messages
    When Send Post Request to "${token_endpoint}" with
      | client_id   | redirect_uri   | code_verifier   | grant_type   | code   |
      | <client_id> | <redirect_uri> | <code_verifier> | <grant_type> | <code> |
    And TGR find request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "<responseCode>"
    And TGR current response at "$.body" matches as JSON:
        """
          {
            "error":                        '.*',
            "____error_description":        '.*',
            "____error_uri":                '.*'
          }
        """
    And TGR current response at "$.body.error" matches "<error>"

    Examples:
      | client_id          | redirect_uri            | code_verifier    | grant_type         | code                  | error           | responseCode |
      | notUrl             | gsi.redirectUri         | gsi.codeVerifier | authorization_code | gsi.authorizationCode | invalid_request | 400          |
      | gsi.clientid.valid | https://invalidRedirect | gsi.codeVerifier | authorization_code | gsi.authorizationCode | invalid_request | 400          |
      | gsi.clientid.valid | gsi.redirectUri         | dasddsad         | authorization_code | gsi.authorizationCode | invalid_request | 400          |
      | gsi.clientid.valid | gsi.redirectUri         | gsi.codeVerifier | password           | gsi.authorizationCode | invalid_request | 400          |
      | gsi.clientid.valid | gsi.redirectUri         | gsi.codeVerifier | authorization_code | eyfsfdsfsd            | invalid_request | 400          |


  @TCID:IDPSEKTORAL_TOKEN_ENDPOINT_004
  @Approval
  Scenario: IdpSektoral Token Endpoint - Negativfall - falsche HTTP Methode

  ```
  Wir senden invaliden Token Request an den sektoralen IDP (GET statt POST)

  Die Response muss als Body eine passende Fehlermeldung enthalten:

    Given TGR clear recorded messages
    When Send Get Request to "${token_endpoint}" with
      | client_id          | redirect_uri    | code_verifier    | grant_type         | code                  |
      | gsi.clientid.valid | gsi.redirectUri | gsi.codeVerifier | authorization_code | gsi.authorizationCode |
    And TGR find request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "405"
    And TGR current response at "$.body" matches as JSON:
        """
          {
            "error":                        'invalid_request',
            "____error_description":        '.*'
          }
        """

  @TCID:IDPSEKTORAL_TOKEN_ENDPOINT_005
    @Approval
  Scenario Outline: IdpSektoral Token Endpoint - Negativfall - fehlende verpflichtende Parameter

  ```
  Wir senden invaliden Token Request an den sektoralen IDP

  Die Response muss als Body eine passende Fehlermeldung enthalten:

    Given TGR clear recorded messages
    When Send Post Request to "${token_endpoint}" with
      | client_id   | redirect_uri   | code_verifier   | grant_type   | code   |
      | <client_id> | <redirect_uri> | <code_verifier> | <grant_type> | <code> |
    And TGR find request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "<responseCode>"
    And TGR current response at "$.body" matches as JSON:
        """
          {
            "error":                        '.*',
            "____error_description":        '.*',
            "____error_uri":                '.*'
          }
        """
    And TGR current response at "$.body.error" matches "<error>"

    Examples:
      | client_id          | redirect_uri    | code_verifier    | grant_type         | code                  | error           | responseCode |
      | $REMOVE            | gsi.redirectUri | gsi.codeVerifier | authorization_code | gsi.authorizationCode | invalid_request | 400          |
      | gsi.clientid.valid | $REMOVE         | gsi.codeVerifier | authorization_code | gsi.authorizationCode | invalid_request | 400          |
      | gsi.clientid.valid | gsi.redirectUri | $REMOVE          | authorization_code | gsi.authorizationCode | invalid_request | 400          |
      | gsi.clientid.valid | gsi.redirectUri | gsi.codeVerifier | $REMOVE            | gsi.authorizationCode | invalid_request | 400          |
      | gsi.clientid.valid | gsi.redirectUri | gsi.codeVerifier | authorization_code | $REMOVE               | invalid_request | 400          |


  @TCID:IDPSEKTORAL_TOKEN_ENDPOINT_006
  @OpenBug
  Scenario: IdpSektoral Token Endpoint - Negativfall - invalid TLS Client Cert

  ```
  Wir senden einen PAR an mit gültigem TLS-C-Zertifikat an den sektoralen IDP, um die Autoregistrierung zu erledigen. Dann senden wir einen Token Request aber verwenden ein
  TLS Client Zertifikat, das nicht im Entity Statement zu der client_id hinterlegt ist.

  Die Response auf den Token Request muss als Body eine passende Fehlermeldung enthalten:

    Given TGR clear recorded messages
    When Send Post Request to "${pushed_authorization_request_endpoint}" with
      | client_id          | state       | redirect_uri    | code_challenge                              | code_challenge_method | response_type | nonce                | scope     | acr_values               |
      | gsi.clientid.valid | yyystateyyy | gsi.redirectUri | 9tI-0CQIkUYaGQOVR1emznlDFjlX0kVY1yd3oiMtGUI | S256                  | code          | vy7rM801AQw1or22GhrZ | gsi.scope | gematik-ehealth-loa-high |
    And TGR find request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "201"
    And TGR clear recorded messages
    When Send Post Request with invalid Client Cert to "${token_endpoint}" with
      | client_id          | redirect_uri    | code_verifier    | grant_type         | code |
      | gsi.clientid.valid | gsi.redirectUri | gsi.codeVerifier | authorization_code | code |
    And TGR find request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "401"
    And TGR current response at "$.body" matches as JSON:
        """
          {
            "error":                        'invalid_request',
            "____error_description":        '.*'
          }
        """
