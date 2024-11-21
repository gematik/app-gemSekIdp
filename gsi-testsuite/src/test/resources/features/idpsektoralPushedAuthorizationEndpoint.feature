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
    Given TGR clear recorded messages
    When TGR sende eine leere GET Anfrage an "${gsi.fachdienstEntityStatementEndpoint}"
    And TGR find request to path ".*/.well-known/openid-federation"
    Then TGR set local variable "pushed_authorization_request_endpoint" to "!{rbel:currentResponseAsString('$..pushed_authorization_request_endpoint')}"
    And TGR HttpClient followRedirects Konfiguration deaktiviert
    And Wait for 1 Seconds

  @TCID:IDPSEKTORAL_PUSHED_AUTH_ENDPOINT_001
    @Approval
    @PRIO:1
    @TESTSTUFE:4
    @OpenBug
  Scenario Outline: IdpSektoral Pushed Auth Endpoint - Gutfall - Validiere Response

  ```
  Wir senden einen PAR an den sektoralen IDP

  Die HTTP Response muss:

  - den Code 201
  - einen json-Body enthalten

    Given TGR clear recorded messages
    When TGR send POST request to "${pushed_authorization_request_endpoint}" with:
      | client_id             | state       | redirect_uri       | code_challenge                              | code_challenge_method | response_type | nonce                | scope        | acr_values   |
      | ${gsi.clientid.valid} | yyystateyyy | ${gsi.redirectUri} | 9tI-0CQIkUYaGQOVR1emznlDFjlX0kVY1yd3oiMtGUI | S256                  | code          | vy7rM801AQw1or22GhrZ | ${gsi.scope} | <acr_values> |
    And TGR find request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "201"
    And TGR current response with attribute "$.header.Content-Type" matches "application/json.*"

    Examples:
      | acr_values                      |
      | gematik-ehealth-loa-high        |
      | gematik-ehealth-loa-substantial |
#      | gematik-ehealth-loa-substantial gematik-ehealth-loa-high |


  @TCID:IDPSEKTORAL_PUSHED_AUTH_ENDPOINT_002
  @Approval
  @PRIO:1
  @TESTSTUFE:4
  @CT
  Scenario: IdpSektoral Pushed Auth Endpoint - Gutfall - Validiere Response Body

  ```
  Wir senden einen PAR an den sektoralen IDP

  Die Response muss als Body eine korrekte json Struktur enthalten:

    Given TGR clear recorded messages
    When TGR send POST request to "${pushed_authorization_request_endpoint}" with:
      | client_id             | state       | redirect_uri       | code_challenge                              | code_challenge_method | response_type | nonce                | scope        | acr_values               |
      | ${gsi.clientid.valid} | yyystateyyy | ${gsi.redirectUri} | 9tI-0CQIkUYaGQOVR1emznlDFjlX0kVY1yd3oiMtGUI | S256                  | code          | vy7rM801AQw1or22GhrZ | ${gsi.scope} | gematik-ehealth-loa-high |
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
  Scenario Outline: IdpSektoral Pushed Auth Endpoint - Negativfall - fehlerhaft befüllte Parameter

  ```
  Wir senden invalide PAR an den sektoralen IDP

  Die Response muss als Body eine passende Fehlermeldung enthalten:

    Given TGR clear recorded messages
    When TGR send POST request to "${pushed_authorization_request_endpoint}" with:
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
    And TGR current response with attribute "$.body.error" matches "<error>"

    Examples:
      | client_id             | redirect_uri            | code_challenge_method | response_type | scope        | acr_values               | error           | responseCode |
      | notUrl                | ${gsi.redirectUri}      | S256                  | code          | ${gsi.scope} | gematik-ehealth-loa-high | invalid_.*      | 40.*         |
      | ${gsi.clientid.valid} | ${gsi.redirectUri}      | plain                 | code          | ${gsi.scope} | gematik-ehealth-loa-high | invalid_request | 400          |
      | ${gsi.clientid.valid} | ${gsi.redirectUri}      | S256                  | token         | ${gsi.scope} | gematik-ehealth-loa-high | .*              | 400          |
      | ${gsi.clientid.valid} | ${gsi.redirectUri}      | S256                  | code          | invalidScope | gematik-ehealth-loa-high | invalid_scope   | 400          |
      | ${gsi.clientid.valid} | ${gsi.redirectUri}      | S256                  | code          | ${gsi.scope} | invalidAcr               | invalid_request | 400          |
      | ${gsi.clientid.valid} | https://invalidRedirect | S256                  | code          | ${gsi.scope} | gematik-ehealth-loa-high | invalid_request | 400          |


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
    Then TGR current response with attribute "$.responseCode" matches "40.*"
    And TGR current response at "$.body" matches as JSON:
        """
          {
            "error":                        '(not_found|invalid_request)',
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
    And TGR current response with attribute "$.body.error" matches "(invalid_request|invalid_scope|unsupported_response_type)"

    Examples:
      | client_id             | redirect_uri       | code_challenge_method | response_type | scope        | acr_values               | responseCode |
      | $REMOVE               | ${gsi.redirectUri} | S256                  | code          | ${gsi.scope} | gematik-ehealth-loa-high | 400          |
      | ${gsi.clientid.valid} | $REMOVE            | S256                  | code          | ${gsi.scope} | gematik-ehealth-loa-high | 400          |
      | ${gsi.clientid.valid} | ${gsi.redirectUri} | $REMOVE               | code          | ${gsi.scope} | gematik-ehealth-loa-high | 400          |
      | ${gsi.clientid.valid} | ${gsi.redirectUri} | S256                  | $REMOVE       | ${gsi.scope} | gematik-ehealth-loa-high | 400          |
      | ${gsi.clientid.valid} | ${gsi.redirectUri} | S256                  | code          | $REMOVE      | gematik-ehealth-loa-high | 400          |


  @TCID:IDPSEKTORAL_PUSHED_AUTH_ENDPOINT_006
  @PRIO:1
  @TESTSTUFE:4
  Scenario: IdpSektoral Pushed Auth Endpoint - Negativfall - invalid TLS Client Cert

  ```
  Wir senden einen PAR an mit gültigem TLS-C-Zertifikat an den sektoralen IDP, um die Autoregistrierung zu erledigen. Dann senden wir einen weiteren PAR aber verwenden ein
  TLS Client Zertifikat, das nicht im Entity Statement zu der client_id hinterlegt ist.

  Die Response auf den zweiten PAR muss als Body eine passende Fehlermeldung enthalten:

    Given TGR clear recorded messages
    When TGR send POST request to "${pushed_authorization_request_endpoint}" with:
      | client_id             | state       | redirect_uri       | code_challenge                              | code_challenge_method | response_type | nonce                | scope        | acr_values               |
      | ${gsi.clientid.valid} | yyystateyyy | ${gsi.redirectUri} | 9tI-0CQIkUYaGQOVR1emznlDFjlX0kVY1yd3oiMtGUI | S256                  | code          | vy7rM801AQw1or22GhrZ | ${gsi.scope} | gematik-ehealth-loa-high |
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
            "error":                        '(invalid_request|invalid_client|unauthorized_client)',
            "____error_description":        '.*'
          }
        """


  @TCID:IDPSEKTORAL_PUSHED_AUTH_ENDPOINT_007
    @PRIO:1
    @TESTSTUFE:4
    @Approval
  Scenario Outline: IdpSektoral Pushed Auth Endpoint - Negativfall - invalide Entity Statements

  ```
  Wir senden einen PAR, um die Autoregistrierung anzustoßen. Das zu der client_id gehörige Entity Statement ist aber ungültig (expired oder ungültige Signatur),
  so dass die Autoregistrierung scheitern muss.

    Given TGR clear recorded messages
    When TGR send POST request to "${pushed_authorization_request_endpoint}" with:
      | client_id   | state       | redirect_uri    | code_challenge                              | code_challenge_method | response_type | nonce                | scope     | acr_values               |
      | <client_id> | yyystateyyy | gsi.redirectUri | 9tI-0CQIkUYaGQOVR1emznlDFjlX0kVY1yd3oiMtGUI | S256                  | code          | vy7rM801AQw1or22GhrZ | gsi.scope | gematik-ehealth-loa-high |
    And TGR find request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "<responseCode>"
    And TGR current response at "$.body" matches as JSON:
        """
          {
            "error":                        '(invalid_request|invalid_client|missing_trust_anchor)',
            "____error_description":        '.*'
          }
        """

    Examples:
      | client_id                        | responseCode |
      | ${gsi.clientid.expired}          | 40.*         |
      | ${gsi.clientid.invalidSignature} | 40.*         |


  @TCID:IDPSEKTORAL_PUSHED_AUTH_ENDPOINT_008
    @Approval
    @PRIO:1
    @TESTSTUFE:4
    @OpenBug
    @Bug:GSI-141
  Scenario Outline: IdpSektoral Pushed Auth Endpoint - Negativfall - Scopes

  ```
  Wir senden einen PAR, um die Autoregistrierung anzustoßen. Bei der zweiten Datenvariante werden mehr scopes angefordert, als im Enity Statement gelistet sind.
  Dieser Request muss abgelehnt werden.

    Given TGR clear recorded messages
    When TGR send POST request to "${pushed_authorization_request_endpoint}" with:
      | client_id             | state       | redirect_uri       | code_challenge                              | code_challenge_method | response_type | nonce                | scope   | acr_values               |
      | ${gsi.clientid.valid} | yyystateyyy | ${gsi.redirectUri} | 9tI-0CQIkUYaGQOVR1emznlDFjlX0kVY1yd3oiMtGUI | S256                  | code          | vy7rM801AQw1or22GhrZ | <scope> | gematik-ehealth-loa-high |
    And TGR find request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "<responseCode>"

    Examples:
      | scope                             | responseCode |
      | ${gsi.scope}                      | 201          |
      | urn:telematik:geburtsdatum openid | 40.*         |


  @TCID:IDPSEKTORAL_PUSHED_AUTH_ENDPOINT_009
    @Approval
    @PRIO:1
    @TESTSTUFE:4
  Scenario Outline: IdpSektoral Pushed Auth Endpoint - Positivfall - Zusätzliche Parameter

  ```
  Wir senden einen PAR, um die Autoregistrierung anzustoßen. Dieser enthält zusätzliche Parameter. Die erste Variante entspricht dem PAR des eRezept-Authservers,
  Die zweite enthält einen unbekannten Parameter. Der IDP muss den PAR akzeptieren.

    Given TGR clear recorded messages
    When TGR send POST request to "${pushed_authorization_request_endpoint}" with:
      | client_id             | state       | redirect_uri       | code_challenge                              | code_challenge_method | response_type | nonce                | scope        | acr_values               | <param_name>  |
      | ${gsi.clientid.valid} | yyystateyyy | ${gsi.redirectUri} | 9tI-0CQIkUYaGQOVR1emznlDFjlX0kVY1yd3oiMtGUI | S256                  | code          | vy7rM801AQw1or22GhrZ | ${gsi.scope} | gematik-ehealth-loa-high | <param_value> |
    And TGR find request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "<responseCode>"

    Examples:
      | param_name            | param_value                                                             | responseCode |
      | client_assertion_type | urn:ietf:params:oauth:client-assertion-type:self_signed_tls_client_auth | 201          |
      | unknown_parameter     | parameter_value                                                         | 201          |


  @TCID:IDPSEKTORAL_PUSHED_AUTH_ENDPOINT_010
    @Akzeptanzfeature
    @Approval
    @PRIO:1
    @TESTSTUFE:4
  Scenario Outline: IdpSektoral Pushed Auth Endpoint - Positivfall - Amr/Acr Kombinationen

  ```
  Wir senden einen PAR, um die Autoregistrierung anzustoßen. Dabei wird der optionale Parameter amr mit verschiedenen Werten mitgeschickt.
  Alle gelisteten Kombinationen sind teilweise gültig/Spec-konform und teilweise genau nicht.
  Der IDP kann auch die invaliden Request akzeptieren und diese invaliden "Vorschläge" dann ignorieren.

    Given TGR clear recorded messages
    When TGR send POST request to "${pushed_authorization_request_endpoint}" with:
      | client_id             | state       | redirect_uri       | code_challenge                              | code_challenge_method | response_type | nonce                | scope        | acr_values   | amr   |
      | ${gsi.clientid.valid} | yyystateyyy | ${gsi.redirectUri} | 9tI-0CQIkUYaGQOVR1emznlDFjlX0kVY1yd3oiMtGUI | S256                  | code          | vy7rM801AQw1or22GhrZ | ${gsi.scope} | <acr_values> | <amr> |
    And TGR find request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "201"

    Examples:
      | acr_values                      | amr                          |
      | gematik-ehealth-loa-high        | urn:telematik:auth:eGK       |
      | gematik-ehealth-loa-high        | urn:telematik:auth:eID       |
      | gematik-ehealth-loa-high        | urn:telematik:auth:sso       |
      | gematik-ehealth-loa-substantial | urn:telematik:auth:mEW       |
      | gematik-ehealth-loa-high        | urn:telematik:auth:guest:eGK |
      | gematik-ehealth-loa-substantial | urn:telematik:auth:other     |
      | gematik-ehealth-loa-high        | urn:telematik:auth:other     |
      | gematik-ehealth-loa-substantial | urn:telematik:auth:eGK       |
      | gematik-ehealth-loa-substantial | urn:telematik:auth:eID       |
      | gematik-ehealth-loa-substantial | urn:telematik:auth:sso       |
      | gematik-ehealth-loa-high        | urn:telematik:auth:mEW       |
      | gematik-ehealth-loa-substantial | urn:telematik:auth:guest:eGK |


  @TCID:IDPSEKTORAL_PUSHED_AUTH_ENDPOINT_012
    @Akzeptanzfeature
    @Approval
    @GematikSekIdpOnly
  Scenario Outline: IdpSektoral Pushed Auth Endpoint - Negativfall - Amr Parameter

  ```
  Wir senden einen PAR, um die Autoregistrierung anzustoßen. Dabei wird der optionale Parameter amr mit verschiedenen invaliden Werten mitgeschickt, die nicht spec-konform sind.

    Given TGR clear recorded messages
    When TGR send POST request to "${pushed_authorization_request_endpoint}" with:
      | client_id             | state       | redirect_uri       | code_challenge                              | code_challenge_method | response_type | nonce                | scope        | acr_values               | amr   |
      | ${gsi.clientid.valid} | yyystateyyy | ${gsi.redirectUri} | 9tI-0CQIkUYaGQOVR1emznlDFjlX0kVY1yd3oiMtGUI | S256                  | code          | vy7rM801AQw1or22GhrZ | ${gsi.scope} | gematik-ehealth-loa-high | <amr> |
    And TGR find request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "400"
    And TGR current response at "$.body" matches as JSON:
        """
          {
            "error":                        'invalid_request',
            "____error_description":        '.*amr: must match.*'
          }
        """

    Examples:
      | amr                    |
      | urn:telematik:auth:nPA |
      | urn:gematik:auth:eID   |
      | any                    |


  @TCID:IDPSEKTORAL_PUSHED_AUTH_ENDPOINT_013
    @Akzeptanzfeature
    @Approval
    @PRIO:1
    @TESTSTUFE:4
  Scenario Outline: IdpSektoral Pushed Auth Endpoint - Gutfall - Prompt Parameter

  ```
  Wir senden einen PAR, um die Autoregistrierung anzustoßen. Dabei wird der optionalen Parameter prompt mit verschiedenen validen Werten mitgeschickt.

    Given TGR clear recorded messages
    When TGR send POST request to "${pushed_authorization_request_endpoint}" with:
      | client_id             | state       | redirect_uri       | code_challenge                              | code_challenge_method | response_type | nonce                | scope        | acr_values               | prompt   |
      | ${gsi.clientid.valid} | yyystateyyy | ${gsi.redirectUri} | 9tI-0CQIkUYaGQOVR1emznlDFjlX0kVY1yd3oiMtGUI | S256                  | code          | vy7rM801AQw1or22GhrZ | ${gsi.scope} | gematik-ehealth-loa-high | <prompt> |
    And TGR find request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "201"

    Examples:
      | prompt         |
      | login          |
      | none           |
      | consent        |
      | select_account |


  @TCID:IDPSEKTORAL_PUSHED_AUTH_ENDPOINT_014
    @Akzeptanzfeature
    @PRIO:1
    @TESTSTUFE:4
    @Approval
  Scenario Outline: IdpSektoral Pushed Auth Endpoint - Negativfall - Prompt Parameter

  ```
  Wir senden einen PAR, um die Autoregistrierung anzustoßen. Dabei wird der optionale Parameter prompt mit invaliden Werten mitgeschickt.
  Keine der gelisteten Kombinationen ist gültig. Der IDP darf diesen Wert aber ignorieren und eine 201 schicken oder mit einer Fehlermeldung ablehnen.

    Given TGR clear recorded messages
    When TGR send POST request to "${pushed_authorization_request_endpoint}" with:
      | client_id             | state       | redirect_uri       | code_challenge                              | code_challenge_method | response_type | nonce                | scope        | acr_values               | prompt   |
      | ${gsi.clientid.valid} | yyystateyyy | ${gsi.redirectUri} | 9tI-0CQIkUYaGQOVR1emznlDFjlX0kVY1yd3oiMtGUI | S256                  | code          | vy7rM801AQw1or22GhrZ | ${gsi.scope} | gematik-ehealth-loa-high | <prompt> |
    And TGR find request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "(201|400)"

    Examples:
      | prompt         |
      | invalid_prompt |

  @TCID:IDPSEKTORAL_PUSHED_AUTH_ENDPOINT_015
    @Akzeptanzfeature
    @Approval
    @PRIO:1
    @TESTSTUFE:4
  Scenario Outline: IdpSektoral Pushed Auth Endpoint - Positivfall - max_age Parameter

  ```
  Wir senden einen PAR, um die Autoregistrierung anzustoßen. Dabei werden die optionalen Parameter max_age mit verschiedenen validen Werten mitgeschickt.
  Die gelisteten Kombinationen sind gültig und müssen akzeptiert werden.

    Given TGR clear recorded messages
    When TGR send POST request to "${pushed_authorization_request_endpoint}" with:
      | client_id             | state       | redirect_uri       | code_challenge                              | code_challenge_method | response_type | nonce                | scope        | acr_values               | max_age   |
      | ${gsi.clientid.valid} | yyystateyyy | ${gsi.redirectUri} | 9tI-0CQIkUYaGQOVR1emznlDFjlX0kVY1yd3oiMtGUI | S256                  | code          | vy7rM801AQw1or22GhrZ | ${gsi.scope} | gematik-ehealth-loa-high | <max_age> |
    And TGR find request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "201"

    Examples:
      | max_age |
      | 0       |
      | 12334   |

  @TCID:IDPSEKTORAL_PUSHED_AUTH_ENDPOINT_016
    @Akzeptanzfeature
    @PRIO:1
    @TESTSTUFE:4
    @Approval
  Scenario Outline: IdpSektoral Pushed Auth Endpoint - Negativfall - max_age Parameter

  ```
  Wir senden einen PAR, um die Autoregistrierung anzustoßen. Dabei werden die optionalen Parameter max_age mit verschiedenen invaliden Werten mitgeschickt.
  Keine der gelisteten Kombinationen ist gültig oder Spec-konform. Der IDP darf diesen Wert aber ignorieren und eine 201 schicken oder mit einer Fehlermeldung ablehnen.

    Given TGR clear recorded messages
    When TGR send POST request to "${pushed_authorization_request_endpoint}" with:
      | client_id             | state       | redirect_uri       | code_challenge                              | code_challenge_method | response_type | nonce                | scope        | acr_values               | max_age   |
      | ${gsi.clientid.valid} | yyystateyyy | ${gsi.redirectUri} | 9tI-0CQIkUYaGQOVR1emznlDFjlX0kVY1yd3oiMtGUI | S256                  | code          | vy7rM801AQw1or22GhrZ | ${gsi.scope} | gematik-ehealth-loa-high | <max_age> |
    And TGR find request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "(201|400)"

    Examples:
      | max_age |
      | -123    |


  @TCID:IDPSEKTORAL_PUSHED_AUTH_ENDPOINT_017
    @Akzeptanzfeature
    @OpenBug
    @PRIO:1
    @TESTSTUFE:4
    @Approval
  Scenario Outline: IdpSektoral Pushed Auth Endpoint - Negativfall - claims Parameter

  ```
  Wir senden einen PAR, um die Autoregistrierung anzustoßen. Dabei wird der optionale Parameter claims mit verschiedenen invaliden Werten mitgeschickt.
  Keine der gelisteten Kombinationen ist gültig. Da die invaliden Claims essential sind, muss der IDP den Request ablehnen.

    Given TGR clear recorded messages
    When TGR send POST request to "${pushed_authorization_request_endpoint}" with:
      | client_id             | state       | redirect_uri       | code_challenge                              | code_challenge_method | response_type | nonce                | scope        | acr_values               | claims   |
      | ${gsi.clientid.valid} | yyystateyyy | ${gsi.redirectUri} | 9tI-0CQIkUYaGQOVR1emznlDFjlX0kVY1yd3oiMtGUI | S256                  | code          | vy7rM801AQw1or22GhrZ | ${gsi.scope} | gematik-ehealth-loa-high | <claims> |
    And TGR find request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "400"

    Examples:
      | claims                                                                           |
      | {"id_token":{"acr":{"essential":true,"values":["gematik-ehealth-loa-invalid"]}}} |
      | {"id_token":{"amr":{"essential":true,"value":"invalidAmr"}}}                     |
      | {"id_token":{"invalid_claim":{"essential":true}}}                                |
      | {"id_token":{"invalid_claim":null}}                                              |


  @TCID:IDPSEKTORAL_PUSHED_AUTH_ENDPOINT_018
    @Akzeptanzfeature
    @PRIO:1
    @TESTSTUFE:4
    @Approval
  Scenario Outline: IdpSektoral Pushed Auth Endpoint - Positivfall - claims Parameter

  ```
  Wir senden einen PAR, um die Autoregistrierung anzustoßen. Dabei wird der optionale Parameter claims mit validen Werten geschickt.
  Die erste Variante ist ein Gastlogin, bei der zweiten können nicht-essential-Claims ignoriert werden.

    Given TGR clear recorded messages
    When TGR send POST request to "${pushed_authorization_request_endpoint}" with:
      | client_id             | state       | redirect_uri       | code_challenge                              | code_challenge_method | response_type | nonce                | scope        | acr_values               | claims   |
      | ${gsi.clientid.valid} | yyystateyyy | ${gsi.redirectUri} | 9tI-0CQIkUYaGQOVR1emznlDFjlX0kVY1yd3oiMtGUI | S256                  | code          | vy7rM801AQw1or22GhrZ | ${gsi.scope} | gematik-ehealth-loa-high | <claims> |
    And TGR find request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "201"

    Examples:
      | claims                                                                                                                                     |
      | {"id_token":{"acr":{"essential":true,"value":"gematik-ehealth-loa-high"},"amr":{"essential":true,"value":"urn:telematik:auth:guest:eGK"}}} |
      | {"id_token":{"acr":{"value":"gematik-ehealth-loa-invalid"}}}                                                                               |
