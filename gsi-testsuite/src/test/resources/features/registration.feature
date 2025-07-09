#
# Copyright (Change Date see Readme), gematik GmbH
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
# *******
#
# For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
#

@Registration
@PRODUKT:IDP-Sek
Feature: Test Fed Master's Entity Statement about IdpSektoral

  Background: Initialisiere Testkontext durch Abfrage des Entity Statements
    Given TGR clear recorded messages
    Given Fetch Fed Master's Entity Statement
    And TGR find first request to path "/.well-known/openid-federation"
    Then TGR set local variable "fedmasterFederationFetchEndpoint" to "!{rbel:currentResponseAsString('$..federation_fetch_endpoint')}"
    Then TGR set local variable "fedmasterIdpListEndpoint" to "!{rbel:currentResponseAsString('$..idp_list_endpoint')}"
    And TGR HttpClient followRedirects Konfiguration deaktiviert

  @TCID:IDPSEKTORAL_FEDM_ENTITY_STATEMENT_001
  @PRIO:1
  @TESTSTUFE:4
  @Approval
  @OpenBug
  Scenario: IdpSektoral - Check Registration in Fed Master's Entity Statement

  ```
  Wir rufen das Entity Statement des Fed Masters über den IdpSektoral ab und prüfen, ob im jwks ein passender Schlüssel steht

    Given TGR clear recorded messages
    When TGR sende eine leere GET Anfrage an "${gsi.fachdienstEntityStatementEndpoint}"
    And TGR find first request to path ".*/.well-known/openid-federation"
    Then TGR set local variable "idpSigKid" to "!{rbel:currentResponseAsString('$.body.header.kid')}"
    Given TGR clear recorded messages
    When Send Get Request to "${fedmasterFederationFetchEndpoint}" with
      | sub        | iss                  |
      | gsi.idpUrl | gsi.fedMasterBaseUrl |
    And TGR find first request to path ".*"
    Then TGR current response at "$.body.body.jwks.keys.[?(@.kid.content == '${idpSigKid}')]" matches as JSON:
            """
          {
            use:                           '.*',
            kid:                           '.*',
            kty:                           'EC',
            crv:                           'P-256',
            x:                             "${json-unit.ignore}",
            y:                             "${json-unit.ignore}",
          }
        """


  @TCID:IDPSEKTORAL_FEDM_ENTITY_STATEMENT_002
  @PRIO:1
  @TESTSTUFE:4
  @Approval
  Scenario: IdpSektoral - Check Registration in Fed Master's IDP List

  ```
  Wir rufen die IDP List des Fed Masters ab und prüfen, ob ein zum sektoralen IDP passender Eintrag vorhanden ist

    Given TGR clear recorded messages
    When Send Get Request to "${fedmasterIdpListEndpoint}"
    And TGR find first request to path ".*"
    Then TGR current response at "$.body.body.idp_entity.[?(@.iss.content == '${gsi.idpUrl}')]" matches as JSON:
        """
            {
              "iss":                    '.*',
              "organization_name":      '.*',
              "logo_uri":               "${json-unit.ignore}",
              "user_type_supported":    "IP"
            }
        """