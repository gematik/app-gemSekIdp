#
# Copyright (Date see Readme), gematik GmbH
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

@IdToken
@PRODUKT:IDP-Sek
Feature: Test IdpSektoral's ID Token

  @TCID:IDPSEKTORAL_ID_TOKEN_001
  @Approval
  @PRIO:1
  @TESTSTUFE:4
  @OpenBug
  @Ticket:GSI-202
  Scenario: IdpSektoral ID Token - Gutfall - validiere Header Claims

  ```
  Wir validieren die Header Claims eines ID Token

    Then Json String "gsi.idToken" at "$.header" matches:
        """
          {
            "alg":                        'ES256',
            "____typ":                        '.*',
            "kid":                        '.*',
            "x5c":                        "${json-unit.ignore}"
          }
        """


  @TCID:IDPSEKTORAL_ID_TOKEN_002
  @Approval
  @PRIO:1
  @TESTSTUFE:4
  Scenario: IdpSektoral ID Token - Gutfall - validiere Body Claims

  ```
  Wir validieren die Body Claims eines ID Token

    Then Json String "gsi.idToken" at "$.body" matches:
        """
          {
            "iss":                                    'http.*',
            "sub":                                    '.*',
            "iat":                                    "${json-unit.ignore}",
            "exp":                                    "${json-unit.ignore}",
            "aud":                                    '.*',
            "nonce":                                  '.*',
            "acr":                                    '(gematik-ehealth-loa-substantial)|(gematik-ehealth-loa-high)',
            "amr":                                    "${json-unit.ignore}",
            "____urn:telematik:claims:profession":        '.*',
            "____urn:telematik:claims:given_name":        '.*',
            "____urn:telematik:claims:organization":      '.*',
            "____urn:telematik:claims:id":                '.*',
            "____at_hash":                            "${json-unit.ignore}",
            "____rat":                                "${json-unit.ignore}",
            "____sid":                                "${json-unit.ignore}",
            "____auth_time":                          "${json-unit.ignore}",
            "____jti":                                "${json-unit.ignore}",
            "____birthdate":                          "${json-unit.ignore}",
            "____urn:barmer:benutzer_id":             "${json-unit.ignore}",
            "____urn:telematik:claims:email":         "${json-unit.ignore}",
            "____urn:telematik:claims:alter":         "${json-unit.ignore}",
            "____urn:telematik:claims:geschlecht":    "${json-unit.ignore}",
            "____urn:telematik:claims:display_name":  "${json-unit.ignore}"
          }
        """
    And Json String "gsi.idToken" at "$.body.amr.0" matches '(urn:telematik:auth:eGK)|(urn:telematik:auth:eID)|(urn:telematik:auth:other)'


  @TCID:IDPSEKTORAL_ID_TOKEN_003
  @Approval
  @PRIO:1
  @TESTSTUFE:4
  Scenario: IdpSektoral ID Token - Gutfall - validiere zeitliche Gültigkeit

  ```
  Wir validieren, dass der ID Token für 300 Sekunden gültig ist

    Then The JWT "gsi.idToken" is vaild for more than 299 but less than 301 seconds