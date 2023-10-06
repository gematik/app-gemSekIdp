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

@AuthorizationEndpoint
@PRODUKT:IDP-Sek
Feature: Test IdpSektoral's Auth Endpoint

  Background: Initialisiere Testkontext durch Abfrage des Entity Statements
    Given Fetch Entity statement
    And TGR find request to path "/.well-known/openid-federation"
    Then TGR set local variable "pushed_authorization_request_endpoint" to "!{rbel:currentResponseAsString('$..pushed_authorization_request_endpoint')}"
    Then TGR set local variable "authorization_endpoint" to "!{rbel:currentResponseAsString('$..authorization_endpoint')}"

  @TCID:IDPSEKTORAL_AUTH_ENDPOINT_001
  @Approval
  @PRIO:1
  @TESTSTUFE:4
  Scenario: IdpSektoral Auth Endpoint - Gutfall - Validiere Response

  ```
  Wir senden einen PAR an den sektoralen IDP. Die resultierende request_uri senden wir dann an den Authorization Endpoint

  Die HTTP Response muss:

  - den Code 200 enthalten

    Given TGR clear recorded messages
    When Send Post Request to "${pushed_authorization_request_endpoint}" with
      | client_id          | state       | redirect_uri    | code_challenge                              | code_challenge_method | response_type | nonce                | scope     | acr_values               |
      | gsi.clientid.valid | yyystateyyy | gsi.redirectUri | 9tI-0CQIkUYaGQOVR1emznlDFjlX0kVY1yd3oiMtGUI | S256                  | code          | vy7rM801AQw1or22GhrZ | gsi.scope | gematik-ehealth-loa-high |
    And TGR find request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "201"
    And TGR set local variable "requestUri" to "!{rbel:currentResponseAsString('$..request_uri')}"
    And TGR clear recorded messages
    When Send Get Request to "${authorization_endpoint}" with
      | request_uri   | client_id          |
      | ${requestUri} | gsi.clientid.valid |
    And TGR find request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "200"


  @TCID:IDPSEKTORAL_AUTH_ENDPOINT_002
    @Approval
    @PRIO:1
    @TESTSTUFE:4
  Scenario Outline: IdpSektoral Auth Endpoint - Negativfall - fehlerhaft befüllte Parameter

  ```
  Wir senden einen invaliden Request an den Authorization Endpoint

  Die Response entspricht der Landingpage. Die Parameter werden im Server inhaltlich nicht geprüft, es wird also keine Fehlermeldung erwartet:

    Given TGR clear recorded messages
    When Send Post Request to "${pushed_authorization_request_endpoint}" with
      | client_id          | state       | redirect_uri    | code_challenge                              | code_challenge_method | response_type | nonce                | scope     | acr_values               |
      | gsi.clientid.valid | yyystateyyy | gsi.redirectUri | 9tI-0CQIkUYaGQOVR1emznlDFjlX0kVY1yd3oiMtGUI | S256                  | code          | vy7rM801AQw1or22GhrZ | gsi.scope | gematik-ehealth-loa-high |
    And TGR find request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "201"
    And TGR set local variable "requestUri" to "!{rbel:currentResponseAsString('$..request_uri')}"
    And TGR clear recorded messages
    When Send Get Request to "${authorization_endpoint}" with
      | request_uri   | client_id   |
      | <request_uri> | <client_id> |
    And TGR find request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "<responseCode>"

    Examples:
      | client_id          | request_uri                                                    | error           | responseCode |
      | gsi.clientid.valid | urn:ietf:params:oauth:request_uri:ZoWuCxe9C8-uW8T3ngvqoYN-stzw | invalid_request | 200          |
      | invalidClient      | ${requestUri}                                                  | invalid_request | 200          |


  @TCID:IDPSEKTORAL_AUTH_ENDPOINT_003
    @Approval
    @PRIO:1
    @TESTSTUFE:4
  Scenario Outline: IdpSektoral Auth Endpoint - Negativfall - fehlende verpflichtende Parameter

  ```
  Wir senden einen invaliden Request an den Authorization Endpoint

  Die Response muss als Body eine passende Fehlermeldung enthalten:

    Given TGR clear recorded messages
    When Send Post Request to "${pushed_authorization_request_endpoint}" with
      | client_id          | state       | redirect_uri    | code_challenge                              | code_challenge_method | response_type | nonce                | scope     | acr_values               |
      | gsi.clientid.valid | yyystateyyy | gsi.redirectUri | 9tI-0CQIkUYaGQOVR1emznlDFjlX0kVY1yd3oiMtGUI | S256                  | code          | vy7rM801AQw1or22GhrZ | gsi.scope | gematik-ehealth-loa-high |
    And TGR find request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "201"
    And TGR set local variable "requestUri" to "!{rbel:currentResponseAsString('$..request_uri')}"
    And TGR clear recorded messages
    When Send Get Request to "${authorization_endpoint}" with
      | request_uri   | client_id   |
      | <request_uri> | <client_id> |
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
      | client_id          | request_uri   | error           | responseCode |
      | gsi.clientid.valid | $REMOVE       | invalid_request | 400          |
      | $REMOVE            | ${requestUri} | invalid_request | 400          |


  @TCID:IDPSEKTORAL_AUTH_ENDPOINT_004
  @LongRunning
  @Approval
  @OpenBug
  @PRIO:1
  @TESTSTUFE:4
  Scenario: IdpSektoral Auth Endpoint - Negativfall - abgelaufene request_uri

  ```
  Wir senden einen PAR an den sektoralen IDP. Die resultierende request_uri senden wir nach mehr als 90 Sekunden an den Authorization Endpoint

  Die Response muss als Body eine passende Fehlermeldung enthalten:

    Given TGR clear recorded messages
    When Send Post Request to "${pushed_authorization_request_endpoint}" with
      | client_id          | state       | redirect_uri    | code_challenge                              | code_challenge_method | response_type | nonce                | scope     | acr_values               |
      | gsi.clientid.valid | yyystateyyy | gsi.redirectUri | 9tI-0CQIkUYaGQOVR1emznlDFjlX0kVY1yd3oiMtGUI | S256                  | code          | vy7rM801AQw1or22GhrZ | gsi.scope | gematik-ehealth-loa-high |
    And TGR find request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "201"
    And TGR set local variable "requestUri" to "!{rbel:currentResponseAsString('$..request_uri')}"
    And TGR clear recorded messages
    And Wait for 100 Seconds
    When Send Get Request to "${authorization_endpoint}" with
      | request_uri   | client_id          |
      | ${requestUri} | gsi.clientid.valid |
    And TGR find request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "400"
    And TGR current response at "$.body" matches as JSON:
        """
          {
            "error":                        '.*',
            "____error_description":        '.*',
            "____error_uri":                '.*'
          }
        """
    And TGR current response at "$.body.error" matches "invalid_request"