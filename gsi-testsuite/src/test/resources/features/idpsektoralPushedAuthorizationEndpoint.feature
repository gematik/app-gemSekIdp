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

@PushedAuthorizationEndpoint
@PRODUKT:IDP-Sek
Feature: Test IdpSektoral's Pushed Auth Endpoint

  Background: Initialisiere Testkontext durch Abfrage des Entity Statements
    Given Fetch Entity statement
    And TGR find request to path "/.well-known/openid-federation"
    Then TGR set local variable "pushed_authorization_request_endpoint" to "!{rbel:currentResponseAsString('$..pushed_authorization_request_endpoint')}"

  @TCID:IDPSEKTORAL_PUSHED_AUTH_ENDPOINT_001
  @Approval
  @PRIO:1
  @TESTSTUFE:4
  Scenario: IdpSektoral Pushed Auth Endpoint - Gutfall - Validiere Response

  ```
  Wir senden einen PAR an den sektoralen IDP

  Die HTTP Response muss:

  - den Code 201
  - einen json-Body enthalten

    Given TGR clear recorded messages
    When Send Post Request to "${pushed_authorization_request_endpoint}" with
      | client_id          | state       | redirect_uri    | code_challenge                              | code_challenge_method | response_type | nonce                | scope     | acr_values               |
      | gsi.clientid.valid | yyystateyyy | gsi.redirectUri | 9tI-0CQIkUYaGQOVR1emznlDFjlX0kVY1yd3oiMtGUI | S256                  | code          | vy7rM801AQw1or22GhrZ | gsi.scope | gematik-ehealth-loa-high |
    And TGR find request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "201"
    And TGR current response with attribute "$.header.Content-Type" matches "application/json.*"


  @TCID:IDPSEKTORAL_PUSHED_AUTH_ENDPOINT_002
  @Approval
  @PRIO:1
  @TESTSTUFE:4
  Scenario: IdpSektoral Pushed Auth Endpoint - Gutfall - Validiere Response Body

  ```
  Wir senden einen PAR an den sektoralen IDP

  Die Response muss als Body eine korrekte json Struktur enthalten:

    Given TGR clear recorded messages
    When Send Post Request to "${pushed_authorization_request_endpoint}" with
      | client_id          | state       | redirect_uri    | code_challenge                              | code_challenge_method | response_type | nonce                | scope     | acr_values               |
      | gsi.clientid.valid | yyystateyyy | gsi.redirectUri | 9tI-0CQIkUYaGQOVR1emznlDFjlX0kVY1yd3oiMtGUI | S256                  | code          | vy7rM801AQw1or22GhrZ | gsi.scope | gematik-ehealth-loa-high |
    And TGR find request to path ".*"
    Then TGR current response at "$.body" matches as JSON:
        """
          {
            "request_uri":       '.*',
            "expires_in":        "${json-unit.ignore}"
          }
        """

  @TCID:IDPSEKTORAL_PUSHED_AUTH_ENDPOINT_003
    @Approval
    @PRIO:1
    @TESTSTUFE:4
  Scenario Outline: IdpSektoral Pushed Auth Endpoint - Negativfall - fehlerhaft befüllte Parameter

  ```
  Wir senden invalide PAR an den sektoralen IDP

  Die Response muss als Body eine passende Fehlermeldung enthalten:

    Given TGR clear recorded messages
    When Send Post Request to "${pushed_authorization_request_endpoint}" with
      | client_id   | state       | redirect_uri   | code_challenge                              | code_challenge_method   | response_type   | nonce                | scope   | acr_values   |
      | <client_id> | yyystateyyy | <redirect_uri> | 9tI-0CQIkUYaGQOVR1emznlDFjlX0kVY1yd3oiMtGUI | <code_challenge_method> | <response_type> | vy7rM801AQw1or22GhrZ | <scope> | <acr_values> |
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
      | client_id          | redirect_uri            | code_challenge_method | response_type | scope        | acr_values               | error           | responseCode |
      | notUrl             | gsi.redirectUri         | S256                  | code          | gsi.scope    | gematik-ehealth-loa-high | invalid_request | 400          |
      | gsi.clientid.valid | gsi.redirectUri         | plain                 | code          | gsi.scope    | gematik-ehealth-loa-high | invalid_request | 400          |
      | gsi.clientid.valid | gsi.redirectUri         | S256                  | token         | gsi.scope    | gematik-ehealth-loa-high | .*              | 400          |
      | gsi.clientid.valid | gsi.redirectUri         | S256                  | code          | invalidScope | gematik-ehealth-loa-high | invalid_scope   | 400          |
      | gsi.clientid.valid | gsi.redirectUri         | S256                  | code          | gsi.scope    | invalidAcr               | invalid_request | 400          |
      | gsi.clientid.valid | https://invalidRedirect | S256                  | code          | gsi.scope    | gematik-ehealth-loa-high | invalid_request | 400          |


  @TCID:IDPSEKTORAL_PUSHED_AUTH_ENDPOINT_004
  @Approval
  @PRIO:1
  @TESTSTUFE:4
  Scenario: IdpSektoral Pushed Auth Endpoint - Negativfall - falsche HTTP Methode

  ```
  Wir senden invalide PAR an den sektoralen IDP (GET statt POST)

  Die Response muss als Body eine passende Fehlermeldung enthalten:

    Given TGR clear recorded messages
    When Send Get Request to "${pushed_authorization_request_endpoint}" with
      | client_id          | state       | redirect_uri    | code_challenge                              | code_challenge_method | response_type | nonce                | scope      | acr_values               |
      | gsi.clientid.valid | yyystateyyy | gsi.redirectUri | 9tI-0CQIkUYaGQOVR1emznlDFjlX0kVY1yd3oiMtGUI | S256                  | code          | vy7rM801AQw1or22GhrZ | gsi.scoped | gematik-ehealth-loa-high |
    And TGR find request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "405"
    And TGR current response at "$.body" matches as JSON:
        """
          {
            "error":                        'invalid_request',
            "____error_description":        '.*'
          }
        """

  @TCID:IDPSEKTORAL_PUSHED_AUTH_ENDPOINT_005
    @Approval
    @PRIO:1
    @TESTSTUFE:4
  Scenario Outline: IdpSektoral Pushed Auth Endpoint - Negativfall - fehlende verpflichtende Parameter

  ```
  Wir senden invalide PAR an den sektoralen IDP

  Die Response muss als Body eine passende Fehlermeldung enthalten:

    Given TGR clear recorded messages
    When Send Post Request to "${pushed_authorization_request_endpoint}" with
      | client_id   | state       | redirect_uri   | code_challenge                              | code_challenge_method   | response_type   | nonce                | scope   | acr_values   |
      | <client_id> | yyystateyyy | <redirect_uri> | 9tI-0CQIkUYaGQOVR1emznlDFjlX0kVY1yd3oiMtGUI | <code_challenge_method> | <response_type> | vy7rM801AQw1or22GhrZ | <scope> | <acr_values> |
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
      | client_id          | redirect_uri    | code_challenge_method | response_type | scope     | acr_values               | error           | responseCode |
      | $REMOVE            | gsi.redirectUri | S256                  | code          | gsi.scope | gematik-ehealth-loa-high | invalid_request | 400          |
      | gsi.clientid.valid | $REMOVE         | S256                  | code          | gsi.scope | gematik-ehealth-loa-high | invalid_request | 400          |
      | gsi.clientid.valid | gsi.redirectUri | $REMOVE               | code          | gsi.scope | gematik-ehealth-loa-high | invalid_request | 400          |
      | gsi.clientid.valid | gsi.redirectUri | S256                  | $REMOVE       | gsi.scope | gematik-ehealth-loa-high | invalid_request | 400          |
      | gsi.clientid.valid | gsi.redirectUri | S256                  | code          | $REMOVE   | gematik-ehealth-loa-high | invalid_request | 400          |
      | gsi.clientid.valid | gsi.redirectUri | S256                  | code          | gsi.scope | $REMOVE                  | invalid_request | 400          |


  @TCID:IDPSEKTORAL_PUSHED_AUTH_ENDPOINT_006
  @PRIO:1
  @TESTSTUFE:4
  Scenario: IdpSektoral Pushed Auth Endpoint - Negativfall - invalid TLS Client Cert

  ```
  Wir senden einen PAR an mit gültigem TLS-C-Zertifikat an den sektoralen IDP, um die Autoregistrierung zu erledigen. Dann senden wir einen weiteren PAR aber verwenden ein
  TLS Client Zertifikat, das nicht im Entity Statement zu der client_id hinterlegt ist.

  Die Response auf den zweiten PAR muss als Body eine passende Fehlermeldung enthalten:

    Given TGR clear recorded messages
    When Send Post Request to "${pushed_authorization_request_endpoint}" with
      | client_id          | state       | redirect_uri    | code_challenge                              | code_challenge_method | response_type | nonce                | scope     | acr_values               |
      | gsi.clientid.valid | yyystateyyy | gsi.redirectUri | 9tI-0CQIkUYaGQOVR1emznlDFjlX0kVY1yd3oiMtGUI | S256                  | code          | vy7rM801AQw1or22GhrZ | gsi.scope | gematik-ehealth-loa-high |
    And TGR find request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "201"
    And TGR clear recorded messages
    When Send Post Request with invalid Client Cert to "${pushed_authorization_request_endpoint}" with
      | client_id          | state       | redirect_uri    | code_challenge                              | code_challenge_method | response_type | nonce                | scope     | acr_values               |
      | gsi.clientid.valid | yyystateyyy | gsi.redirectUri | 9tI-0CQIkUYaGQOVR1emznlDFjlX0kVY1yd3oiMtGUI | S256                  | code          | vy7rM801AQw1or22GhrZ | gsi.scope | gematik-ehealth-loa-high |
    And TGR find request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "401"
    And TGR current response at "$.body" matches as JSON:
        """
          {
            "error":                        'invalid_request',
            "____error_description":        '.*'
          }
        """


  @TCID:IDPSEKTORAL_PUSHED_AUTH_ENDPOINT_007
    @PRIO:1
    @TESTSTUFE:4
  Scenario Outline: IdpSektoral Pushed Auth Endpoint - Negativfall - invalide Entity Statements

  ```
  Wir senden einen PAR, um die Autoregistrierung anzustoßen. Das zu der client_id gehörige Entity Statement ist aber ungültig (expired oder ungültige Signatur),
  so dass die Autoregistrierung scheitern muss.

    Given TGR clear recorded messages
    When Send Post Request to "${pushed_authorization_request_endpoint}" with
      | client_id   | state       | redirect_uri    | code_challenge                              | code_challenge_method | response_type | nonce                | scope     | acr_values               |
      | <client_id> | yyystateyyy | gsi.redirectUri | 9tI-0CQIkUYaGQOVR1emznlDFjlX0kVY1yd3oiMtGUI | S256                  | code          | vy7rM801AQw1or22GhrZ | gsi.scope | gematik-ehealth-loa-high |
    And TGR find request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "<responseCode>"
    And TGR current response at "$.body" matches as JSON:
        """
          {
            "error":                        'invalid_request',
            "____error_description":        '.*'
          }
        """

    Examples:
      | client_id                     | responseCode |
      | gsi.clientid.expired          | 401          |
      | gsi.clientid.invalidSignature | 401          |