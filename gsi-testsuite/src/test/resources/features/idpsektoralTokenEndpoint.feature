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

@TokenEndpoint
@PRODUKT:IDP-Sek
Feature: Test IdpSektoral's Token Endpoint

  Background: Initialisiere Testkontext durch Abfrage des Entity Statements
    When TGR sende eine leere GET Anfrage an "${gsi.fachdienstEntityStatementEndpoint}"
    And TGR find request to path ".*/.well-known/openid-federation"
    Then TGR set local variable "pushed_authorization_request_endpoint" to "!{rbel:currentResponseAsString('$..pushed_authorization_request_endpoint')}"
    Then TGR set local variable "authorization_endpoint" to "!{rbel:currentResponseAsString('$..authorization_endpoint')}"
    Then TGR set local variable "token_endpoint" to "!{rbel:currentResponseAsString('$..token_endpoint')}"


  @TCID:IDPSEKTORAL_TOKEN_ENDPOINT_001
    @Approval
    @PRIO:1
    @TESTSTUFE:4
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
    And TGR current response with attribute "$.body.error" matches "(invalid_request)|(invalid_grant)|(invalid_client)|(unsupported_grant_type)"

    Examples:
      | client_id          | redirect_uri            | code_verifier    | grant_type         | code                  | responseCode |
      | notUrl             | gsi.redirectUri         | gsi.codeVerifier | authorization_code | gsi.authorizationCode | 40.*         |
      | gsi.clientid.valid | https://invalidRedirect | gsi.codeVerifier | authorization_code | gsi.authorizationCode | 400          |
      | gsi.clientid.valid | gsi.redirectUri         | dasddsad         | authorization_code | gsi.authorizationCode | 400          |
      | gsi.clientid.valid | gsi.redirectUri         | gsi.codeVerifier | password           | gsi.authorizationCode | 400          |
      | gsi.clientid.valid | gsi.redirectUri         | gsi.codeVerifier | authorization_code | eyfsfdsfsd            | 400          |


  @TCID:IDPSEKTORAL_TOKEN_ENDPOINT_002
  @Approval
  @PRIO:1
  @TESTSTUFE:4
  Scenario: IdpSektoral Token Endpoint - Negativfall - falsche HTTP Methode

  ```
  Wir senden invaliden Token Request an den sektoralen IDP (GET statt POST)

  Die Response muss als Body eine passende Fehlermeldung enthalten:

    Given TGR clear recorded messages
    When Send Get Request to "${token_endpoint}" with
      | client_id          | redirect_uri    | code_verifier    | grant_type         | code                  |
      | gsi.clientid.valid | gsi.redirectUri | gsi.codeVerifier | authorization_code | gsi.authorizationCode |
    And TGR find request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "(404|405)"
    And TGR current response at "$.body" matches as JSON:
        """
          {
            "error":                        '.*',
            "____error_description":        '.*'
          }
        """

  @TCID:IDPSEKTORAL_TOKEN_ENDPOINT_003
    @Approval
    @PRIO:1
    @TESTSTUFE:4
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
    And TGR current response with attribute "$.body.error" matches "(invalid_request)|(invalid_grant)"

    Examples:
      | client_id          | redirect_uri    | code_verifier    | grant_type         | code                  | responseCode |
      | $REMOVE            | gsi.redirectUri | gsi.codeVerifier | authorization_code | gsi.authorizationCode | 40.*         |
      | gsi.clientid.valid | $REMOVE         | gsi.codeVerifier | authorization_code | gsi.authorizationCode | 400          |
      | gsi.clientid.valid | gsi.redirectUri | $REMOVE          | authorization_code | gsi.authorizationCode | 400          |
      | gsi.clientid.valid | gsi.redirectUri | gsi.codeVerifier | $REMOVE            | gsi.authorizationCode | 400          |
      | gsi.clientid.valid | gsi.redirectUri | gsi.codeVerifier | authorization_code | $REMOVE               | 400          |


  @TCID:IDPSEKTORAL_TOKEN_ENDPOINT_004
  @PRIO:1
  @TESTSTUFE:4
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
    Then TGR current response with attribute "$.responseCode" matches "(400|401)"
    And TGR current response at "$.body" matches as JSON:
        """
          {
            "error":                        'invalid_.*',
            "____error_description":        '.*'
          }
        """


  @TCID:IDPSEKTORAL_TOKEN_ENDPOINT_005
  @Approval
  @GematikSekIdpOnly
  Scenario: IdpSektoral Token Endpoint - Gutfall - rufe ID_TOKEN ab

  ```
  Wir senden einen PAR an den sektoralen IDP. Die resultierende request_uri senden wir dann an den Authorization Endpoint, um anschließend nochmal mit
  der user_id zu demselben Endpunkt zu gehen. Den resultierenden authorization_code lösen wir ein

  Die HTTP Response muss:

  - der richtigen json-body enthalten

    Given TGR clear recorded messages
    When Send Post Request to "${pushed_authorization_request_endpoint}" with
      | client_id          | state       | redirect_uri    | code_challenge                              | code_challenge_method | response_type | nonce                | scope     | acr_values               |
      | gsi.clientid.valid | yyystateyyy | gsi.redirectUri | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | code          | vy7rM801AQw1or22GhrZ | gsi.scope | gematik-ehealth-loa-high |
    And TGR find request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "201"
    And TGR set local variable "requestUri" to "!{rbel:currentResponseAsString('$..request_uri')}"
    And TGR clear recorded messages
    When Send Get Request to "${authorization_endpoint}" with
      | request_uri   | client_id          |
      | ${requestUri} | gsi.clientid.valid |
    And TGR find request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "200"
    And TGR clear recorded messages
    When Send Get Request to "${authorization_endpoint}" with
      | request_uri   | user_id  |
      | ${requestUri} | 12345678 |
    And TGR find request to path ".*"
    And TGR set local variable "authCode" to "!{rbel:currentResponseAsString('$.header.Location.code.value')}"
    Given TGR clear recorded messages
    When Send Post Request to "${token_endpoint}" with
      | client_id          | redirect_uri    | code_verifier                                                                      | grant_type         | code        |
      | gsi.clientid.valid | gsi.redirectUri | drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj | authorization_code | ${authCode} |
    And TGR find request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "200"
    And TGR current response with attribute "$.header.Content-Type" matches "application/json.*"


  @TCID:IDPSEKTORAL_TOKEN_ENDPOINT_006
  @Approval
  @GematikSekIdpOnly
  Scenario: IdpSektoral Token Endpoint - Gutfall - validiere ID_TOKEN Header Claims

  ```
  Wir senden einen PAR an den sektoralen IDP. Die resultierende request_uri senden wir dann an den Authorization Endpoint, um anschließend nochmal mit
  der user_id zu demselben Endpunkt zu gehen. Den resultierenden authorization_code lösen wir ein

  Der verschlüsselte ID_TOKEN muss:

  - die richtigen encryption Header haben

    Given TGR clear recorded messages
    When Send Post Request to "${pushed_authorization_request_endpoint}" with
      | client_id          | state       | redirect_uri    | code_challenge                              | code_challenge_method | response_type | nonce                | scope     | acr_values               |
      | gsi.clientid.valid | yyystateyyy | gsi.redirectUri | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | code          | vy7rM801AQw1or22GhrZ | gsi.scope | gematik-ehealth-loa-high |
    And TGR find request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "201"
    And TGR set local variable "requestUri" to "!{rbel:currentResponseAsString('$..request_uri')}"
    And TGR clear recorded messages
    When Send Get Request to "${authorization_endpoint}" with
      | request_uri   | client_id          |
      | ${requestUri} | gsi.clientid.valid |
    And TGR find request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "200"
    And TGR clear recorded messages
    When Send Get Request to "${authorization_endpoint}" with
      | request_uri   | user_id  |
      | ${requestUri} | 12345678 |
    And TGR find request to path ".*"
    And TGR set local variable "authCode" to "!{rbel:currentResponseAsString('$.header.Location.code.value')}"
    Given TGR clear recorded messages
    When Send Post Request to "${token_endpoint}" with
      | client_id          | redirect_uri    | code_verifier                                                                      | grant_type         | code        |
      | gsi.clientid.valid | gsi.redirectUri | drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj | authorization_code | ${authCode} |
    And TGR find request to path ".*"
    Then TGR current response at "$.body.id_token.content.header" matches as JSON:
    """
      {
        "alg": "ECDH-ES",
        "enc": "A256GCM",
        "cty": "JWT",
        "kid": "puk_fd_enc",
        "epk": {
          "kty": "EC",
          "x": '.*',
          "y": '.*',
          "crv": "P-256"
        }
      }
    """


  @TCID:IDPSEKTORAL_TOKEN_ENDPOINT_007
  @Approval
  @GematikSekIdpOnly
  Scenario: IdpSektoral Token Endpoint - Negativfall - Fehlerhafter code_verifier

  ```
  Wir senden einen PAR an den sektoralen IDP. Die resultierende request_uri senden wir dann an den Authorization Endpoint, um anschließend nochmal mit
  der user_id zu demselben Endpunkt zu gehen. Den resultierenden authorization_code lösen wir ein

  Die HTTP Response muss:

  - die richtige Fehlermeldung enthalten

    Given TGR clear recorded messages
    When Send Post Request to "${pushed_authorization_request_endpoint}" with
      | client_id          | state       | redirect_uri    | code_challenge                              | code_challenge_method | response_type | nonce                | scope     | acr_values               |
      | gsi.clientid.valid | yyystateyyy | gsi.redirectUri | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | code          | vy7rM801AQw1or22GhrZ | gsi.scope | gematik-ehealth-loa-high |
    And TGR find request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "201"
    And TGR set local variable "requestUri" to "!{rbel:currentResponseAsString('$..request_uri')}"
    And TGR clear recorded messages
    When Send Get Request to "${authorization_endpoint}" with
      | request_uri   | client_id          |
      | ${requestUri} | gsi.clientid.valid |
    And TGR find request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "200"
    And TGR clear recorded messages
    When Send Get Request to "${authorization_endpoint}" with
      | request_uri   | user_id  |
      | ${requestUri} | 12345678 |
    And TGR find request to path ".*"
    And TGR set local variable "authCode" to "!{rbel:currentResponseAsString('$.header.Location.code.value')}"
    Given TGR clear recorded messages
    When Send Post Request to "${token_endpoint}" with
      | client_id          | redirect_uri    | code_verifier   | grant_type         | code        |
      | gsi.clientid.valid | gsi.redirectUri | invalidverifier | authorization_code | ${authCode} |
    And TGR find request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "400"
    And TGR current response at "$.body" matches as JSON:
        """
          {
            "error":                        'invalid_request',
            "____error_description":        '.*'
          }
        """


  @TCID:IDPSEKTORAL_TOKEN_ENDPOINT_008
    @Approval
    @GematikSekIdpOnly
  Scenario Outline: IdpSektoral Token Endpoint - Gutfall ohne userConsent - validiere ID_TOKEN Body Claims

  ```
  Wir senden einen PAR an den sektoralen IDP. Die resultierende request_uri senden wir dann an den Authorization Endpoint, um anschließend den Flow über mit der
  Abkürzung ohne UserConsent abzuschließen. Den resultierenden authorization_code lösen wir ein

  Der ID_TOKEN muss die richtigen Bodyclaims besitzen:

    Given TGR clear recorded messages
    When Send Post Request to "${pushed_authorization_request_endpoint}" with
      | client_id          | state       | redirect_uri    | code_challenge                              | code_challenge_method | response_type | nonce                | scope     | acr_values               |
      | gsi.clientid.valid | yyystateyyy | gsi.redirectUri | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | code          | vy7rM801AQw1or22GhrZ | gsi.scope | gematik-ehealth-loa-high |
    And TGR find request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "201"
    And TGR set local variable "requestUri" to "!{rbel:currentResponseAsString('$..request_uri')}"
    And TGR clear recorded messages
    When Send Get Request to "${authorization_endpoint}" with
      | request_uri   | user_id  |
      | ${requestUri} | <userId> |
    And TGR find request to path ".*"
    And TGR set local variable "authCode" to "!{rbel:currentResponseAsString('$.header.Location.code.value')}"
    Given TGR clear recorded messages
    When Send Post Request to "${token_endpoint}" with
      | client_id          | redirect_uri    | code_verifier                                                                      | grant_type         | code        |
      | gsi.clientid.valid | gsi.redirectUri | drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj | authorization_code | ${authCode} |
    And TGR find request to path ".*"
    Then TGR current response at "$.body.id_token.content.body.body" matches as JSON:
    """
      {
      "sub": '.*',
      "aud": '.*',
      "acr": "gematik-ehealth-loa-high",
      "urn:telematik:claims:id": "<id>",
      "urn:telematik:claims:organization": "<organization>",
      "urn:telematik:claims:profession": "1.2.276.0.76.4.49",
      "urn:telematik:claims:display_name": "<displayName>",
      "amr": '.*',
      "iss": '.*',
      "exp": "${json-unit.ignore}",
      "iat": "${json-unit.ignore}",
      "nonce": '.*'
      }
    """
    Examples:
      | userId     | id         | organization | displayName                                 |
      | 12345678   | X110411675 | 109500969    | Darius Michael Brian Ubbo Graf von Bödefeld |
      | D162565246 | D162565246 | 101592612    | Imagina Handt                               |


  @TCID:IDPSEKTORAL_TOKEN_ENDPOINT_009
  @Approval
  @GematikSekIdpOnly
  Scenario: IdpSektoral Token Endpoint - Gutfall mit userConsent - validiere ID_TOKEN Body Claims

  ```
  Wir senden einen PAR an den sektoralen IDP. Die resultierende request_uri senden wir dann an den Authorization Endpoint, um anschließend den Flow über den Pfad mit
  UserConsent abzuschließen. Den resultierenden authorization_code lösen wir ein

  Der verschlüsselte ID_TOKEN muss die richtigen Claims besitzen:

    Given TGR clear recorded messages
    When Send Post Request to "${pushed_authorization_request_endpoint}" with
      | client_id          | state       | redirect_uri    | code_challenge                              | code_challenge_method | response_type | nonce                | scope                             | acr_values               |
      | gsi.clientid.valid | yyystateyyy | gsi.redirectUri | Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg | S256                  | code          | vy7rM801AQw1or22GhrZ | urn:telematik:versicherter openid | gematik-ehealth-loa-high |
    And TGR find request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "201"
    And TGR set local variable "requestUri" to "!{rbel:currentResponseAsString('$..request_uri')}"
    And TGR clear recorded messages
    When Send Get Request to "${authorization_endpoint}" with
      | request_uri   | device_type |
      | ${requestUri} | testsuite   |
    And TGR find request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "200"
    And TGR clear recorded messages
    When Send Get Request to "${authorization_endpoint}" with
      | request_uri   | user_id  | selected_claims                 |
      | ${requestUri} | 12345678 | urn:telematik:claims:profession |
    And TGR find request to path ".*"
    And TGR set local variable "authCode" to "!{rbel:currentResponseAsString('$.header.Location.code.value')}"
    Given TGR clear recorded messages
    When Send Post Request to "${token_endpoint}" with
      | client_id          | redirect_uri    | code_verifier                                                                      | grant_type         | code        |
      | gsi.clientid.valid | gsi.redirectUri | drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj | authorization_code | ${authCode} |
    And TGR find request to path ".*"
    Then TGR current response at "$.body.id_token.content.body.body" matches as JSON:
    """
      {
      "sub": '.*',
      "aud": '.*',
      "acr": "gematik-ehealth-loa-high",
      "urn:telematik:claims:profession": "1.2.276.0.76.4.49",
      "amr": '.*',
      "iss": '.*',
      "exp": "${json-unit.ignore}",
      "iat": "${json-unit.ignore}",
      "nonce": '.*'
      }
    """