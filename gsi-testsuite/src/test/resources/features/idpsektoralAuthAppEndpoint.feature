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

@AuthAppEndpoint
@GematikSekIdpOnly
Feature: Test IdpSektoral's Auth Endpoint

  Background: Initialisiere Testkontext durch Abfrage des Entity Statements
    Given Fetch Entity statement
    And TGR find request to path "/.well-known/openid-federation"
    Then TGR set local variable "pushed_authorization_request_endpoint" to "!{rbel:currentResponseAsString('$..pushed_authorization_request_endpoint')}"
    Then TGR set local variable "authorization_endpoint" to "!{rbel:currentResponseAsString('$..authorization_endpoint')}"

  @TCID:IDPSEKTORAL_AUTHAPP_ENDPOINT_001
  @Approval
  Scenario: IdpSektoral AuthApp Endpoint - Gutfall - Validiere Response

  ```
  Wir senden einen PAR (Nachricht 2) an den sektoralen IDP und anschließend senden wir einen URI-PAR (Nachricht 6)

  Die HTTP Response muss:

  - den Code 302
  - einen Authorization Code in der Location

    Given TGR clear recorded messages
    When Send Post Request to "${pushed_authorization_request_endpoint}" with
      | client_id          | state       | redirect_uri    | code_challenge                              | code_challenge_method | response_type | nonce                | scope     | acr_values               |
      | gsi.clientid.valid | yyystateyyy | gsi.redirectUri | 9tI-0CQIkUYaGQOVR1emznlDFjlX0kVY1yd3oiMtGUI | S256                  | code          | vy7rM801AQw1or22GhrZ | gsi.scope | gematik-ehealth-loa-high |
    And TGR find request to path "/PAR_Auth"
    Then TGR set local variable "parRequestUri" to "!{rbel:currentResponseAsString('$..request_uri')}"
    When Send Get Request to "${authorization_endpoint}/app" with
      | request_uri   |
      | parRequestUri |
    And TGR find request to path "/auth/app"
    Then TGR current response with attribute "$.responseCode" matches "302"
    And TGR current response at "$.header.Location" matches "${gsi.redirectUri}?.*code=.*"
    And TGR current response at "$.header.Location" matches ".*state=yyystateyyy.*"


  @TCID:IDPSEKTORAL_AUTHAPP_ENDPOINT_002
  @OpenBug(GSI-21)
  Scenario: IdpSektoral AuthApp Endpoint - Negativfall - Validiere Response

  ```
  Wir senden einen PAR (Nachricht 2) an den sektoralen IDP und anschließend senden wir einen fehlerhaften URI-PAR (Nachricht 6)

  Die HTTP Response muss:

  - den Code 302
  - eine Fehlermeldung in der Location

    Given TGR clear recorded messages
    When Send Post Request to "${pushed_authorization_request_endpoint}" with
      | client_id          | state       | redirect_uri    | code_challenge                              | code_challenge_method | response_type | nonce                | scope     | acr_values               |
      | gsi.clientid.valid | yyystateyyy | gsi.redirectUri | 9tI-0CQIkUYaGQOVR1emznlDFjlX0kVY1yd3oiMtGUI | S256                  | code          | vy7rM801AQw1or22GhrZ | gsi.scope | gematik-ehealth-loa-high |
    And TGR find request to path "/PAR_Auth"
    Then TGR set local variable "parRequestUri" to "!{rbel:currentResponseAsString('$..request_uri')}"
    When Send Get Request to "${authorization_endpoint}/app" with
      | request_uri     |
      | urn:invalid:666 |
    And TGR find request to path "/auth/app"
    Then TGR current response with attribute "$.responseCode" matches "302"
    And TGR current response at "$.header.Location" matches "${gsi.redirectUri}?.*code=.*"
    And TGR current response at "$.header.Location" matches ".*state=yyystateyyy.*"
