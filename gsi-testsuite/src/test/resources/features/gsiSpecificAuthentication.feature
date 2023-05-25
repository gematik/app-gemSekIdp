#
# Copyright [2023] gematik GmbH
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
@GematikSekIdpOnly
Feature: Test GSI specific authentication

  Background: Initialisiere Testkontext durch Abfrage des Entity Statements
    Given Fetch Entity statement
    And TGR find request to path "/.well-known/openid-federation"
    Then TGR set local variable "pushed_authorization_request_endpoint" to "!{rbel:currentResponseAsString('$..pushed_authorization_request_endpoint')}"
    Then TGR set local variable "authorization_endpoint" to "!{rbel:currentResponseAsString('$..authorization_endpoint')}"

  @TCID:GSI_AUTH_001
  @Approval
  Scenario: GSI Authentication - Gutfall - Validiere Response

  ```
  Wir senden einen PAR an den sektoralen IDP. Die resultierende request_uri senden wir dann an den Authorization Endpoint, um anschließend nochmal mit
  der user_id zu demselben Endpunkt zu gehen

  Die HTTP Response muss:

  - den Code 302 enthalten

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
    Then TGR current response with attribute "$.responseCode" matches "302"
    And TGR clear recorded messages
    When Send Get Request to "${authorization_endpoint}" with
      | request_uri   | user_id  |
      | ${requestUri} | 12345678 |
    And TGR find request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "302"


  @TCID:GSI_AUTH_002
  @Approval
  Scenario: GSI Authentication - Gutfall - Validiere Code in Location

  ```
  Wir senden einen PAR an den sektoralen IDP. Die resultierende request_uri senden wir dann an den Authorization Endpoint, um anschließend nochmal mit
  der user_id zu demselben Endpunkt zu gehen

  Die HTTP Response muss:

  - den Authorization Code enthalten

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
    Then TGR current response with attribute "$.responseCode" matches "302"
    And TGR clear recorded messages
    When Send Get Request to "${authorization_endpoint}" with
      | request_uri   | user_id  |
      | ${requestUri} | 12345678 |
    And TGR find request to path ".*"
    Then TGR current response with attribute "$.header.Location" matches ".*code=.*"

  @TCID:GSI_AUTH_003
    @Approval
    @OpenBug
  Scenario Outline: GSI Authentication - Negativfall - invalide Werter für die Parameter

  ```
  Wir senden einen PAR an den sektoralen IDP. Die resultierende request_uri senden wir dann an den Authorization Endpoint, um anschließend nochmal mit
  falsch befüllten Parametern zu demselben Endpunkt zu gehen.

  Die HTTP Response muss eine Fehlermeldung per redirect enthalten

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
    Then TGR current response with attribute "$.responseCode" matches "302"
    And TGR clear recorded messages
    When Send Get Request to "${authorization_endpoint}" with
      | request_uri       | user_id       |
      | <requestUriExmpl> | <userIdExmpl> |
    And TGR find request to path ".*"
    Then TGR current response with attribute "$.header.Location" matches "<errorExmpl>"

    Examples:
      | requestUriExmpl | userIdExmpl   | errorExmpl                |
      | invalidReqUri   | 12345678      | .*error=invalid_request.* |
      | ${requestUri}   | 12345678      | .*error=invalid_request.* |
      | ${requestUri}   | invalidUserId | .*error=invalid_request.* |


  @TCID:GSI_AUTH_004
  @Approval
  @OpenBug
  Scenario: GSI Authentication - Negativfall - fehlende Parameter

  ```
  Wir senden einen PAR an den sektoralen IDP. Die resultierende request_uri senden wir dann an den Authorization Endpoint, um anschließend nochmal mit
  fehlenden Parametern zu demselben Endpunkt zu gehen

  Die HTTP Response muss eine Fehlermeldung per redirect enthalten

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
    Then TGR current response with attribute "$.responseCode" matches "302"
    And TGR clear recorded messages
    When Send Get Request to "${authorization_endpoint}" with
      | user_id  |
      | 12345678 |
    And TGR find request to path ".*"
    Then TGR current response with attribute "$.header.Location" matches ".*error=invalid_request.*"
