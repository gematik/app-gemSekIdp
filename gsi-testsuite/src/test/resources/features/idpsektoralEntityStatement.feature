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

@EntityStatement
@PRODUKT:IDP-Sek
Feature: Test Entity Statement of IdpSektoral

  Background: Initialisiere Testkontext durch Abfrage des Entity Statements
    When TGR sende eine leere GET Anfrage an "${gsi.fachdienstEntityStatementEndpoint}"
    And TGR find first request to path ".*/.well-known/openid-federation"
    And Expect JWKS in last message and add its keys to truststore

  @TCID:IDPSEKTORAL_ENTITY_STATEMENT_001
  @Approval
  @PRIO:1
  @TESTSTUFE:4
  @CT
  Scenario: IdpSektoral Signature - Check Entity Statement

  ```
  Wir rufen das Entity Statement des IdpSektoral ab und prüfen, ob die Signatur korrekt ist

    Given TGR clear recorded messages
    When TGR sende eine leere GET Anfrage an "${gsi.fachdienstEntityStatementEndpoint}"
    And TGR find first request to path ".*/.well-known/openid-federation"
    And Check signature of JWS in last message

  @TCID:IDPSEKTORAL_ENTITY_STATEMENT_002
  @Approval
  @PRIO:1
  @TESTSTUFE:4
  Scenario: IdpSektoral EntityStatement - Gutfall - Validiere Response

  ```
  Wir rufen zwei Mal das EntityStatement beim IdpSektoral ab. Bei dem zweiten Abruf fordern wir über den Accept-Header explizit den korrekten Content-Type ab.

  Die HTTP Response muss in beiden Fällen:

  - den Code 200,
  - einen JWS und
  - den Content-Type application/entity-statement\+jwt.* enthalten

    Given TGR clear recorded messages
    When TGR sende eine leere GET Anfrage an "${gsi.fachdienstEntityStatementEndpoint}"
    And TGR find first request to path ".*/.well-known/openid-federation"
    Then TGR current response with attribute "$.responseCode" matches "200"
    And TGR current response with attribute "$.header.Content-Type" matches "application/entity-statement\+jwt.*"
    Given TGR clear recorded messages
    When TGR send empty GET request to "${gsi.fachdienstEntityStatementEndpoint}" with headers:
      | Accept | application/entity-statement+jwt |
    And TGR find first request to path ".*/.well-known/openid-federation"
    Then TGR current response with attribute "$.responseCode" matches "200"
    And TGR current response with attribute "$.header.Content-Type" matches "application/entity-statement\+jwt.*"


  @TCID:IDPSEKTORAL_ENTITY_STATEMENT_003
  @Approval
  @PRIO:1
  @TESTSTUFE:4
  Scenario: IdpSektoral EntityStatement - Gutfall - Validiere Response Header Claims

  ```
  Wir rufen das EntityStatement beim IdpSektoral ab

  Der Response Body muss ein JWS mit den folgenden Header Claims sein:

    Given TGR clear recorded messages
    When TGR sende eine leere GET Anfrage an "${gsi.fachdienstEntityStatementEndpoint}"
    And TGR find first request to path ".*/.well-known/openid-federation"
    Then TGR current response at "$.body.header" matches as JSON:
            """
          {
          alg:        'ES256',
          kid:        '.*',
          typ:        'entity-statement+jwt'
          }
        """

  @TCID:IDPSEKTORAL_ENTITY_STATEMENT_004
  @Approval
  @PRIO:1
  @TESTSTUFE:4
  Scenario: IdpSektoral EntityStatement - Gutfall - Validiere Response Body Claims

  ```
  Wir rufen das EntityStatement beim IdpSektoral ab

  Der Response Body muss ein JWS mit den korrekten Body Claims sein:

    Given TGR clear recorded messages
    When TGR sende eine leere GET Anfrage an "${gsi.fachdienstEntityStatementEndpoint}"
    And TGR find first request to path ".*/.well-known/openid-federation"
    Then TGR current response at "$.body.body" matches as JSON:
            """
          {
            iss:                           'http.*',
            sub:                           'http.*',
            iat:                           "${json-unit.ignore}",
            exp:                           "${json-unit.ignore}",
            jwks:                          "${json-unit.ignore}",
            authority_hints:               "${json-unit.ignore}",
            metadata:                      "${json-unit.ignore}"
          }
        """

  @TCID:IDPSEKTORAL_ENTITY_STATEMENT_005
  @Approval
  @PRIO:1
  @TESTSTUFE:4
  Scenario: IdpSektoral EntityStatement - Gutfall - Validiere Metadata Body Claim

  ```
  Wir rufen das EntityStatement beim IdpSektoral ab

  Der Response Body muss ein JWS sein. Dieser muss einen korrekt aufgebauten Body Claim metadata enthalten

    Given TGR clear recorded messages
    When TGR sende eine leere GET Anfrage an "${gsi.fachdienstEntityStatementEndpoint}"
    And TGR find first request to path ".*/.well-known/openid-federation"
    Then TGR current response at "$.body.body.metadata" matches as JSON:
    """
          {
            openid_provider:                           "${json-unit.ignore}"
          }
    """
    And TGR current response at "$.body.body.metadata.openid_provider" matches as JSON:
    """
          {
            issuer:                                       'http.*',
            signed_jwks_uri:                              'http.*',
            authorization_endpoint:                       'http.*',
            token_endpoint:                               'http.*',
            pushed_authorization_request_endpoint:        'http.*',
            organization_name:                            '.*',
            keywords:                                     "${json-unit.ignore}",
            contacts:                                     "${json-unit.ignore}",
            logo_uri:                                     'http.*',
            client_registration_types_supported:          ["automatic"],
            subject_types_supported:                      ["pairwise"],
            response_types_supported:                     "${json-unit.ignore}",
            scopes_supported:                             "${json-unit.ignore}",
            claims_supported:                             "${json-unit.ignore}",
            claims_parameter_supported:                   true,
            response_modes_supported:                     ["query"],
            grant_types_supported:                        ["authorization_code"],
            require_pushed_authorization_requests:        true,
            token_endpoint_auth_methods_supported:        [self_signed_tls_client_auth],
            id_token_signing_alg_values_supported:        ["ES256"],
            id_token_encryption_alg_values_supported:     ["ECDH-ES"],
            id_token_encryption_enc_values_supported:     ["A256GCM"],
            user_type_supported:                          ["IP"],
            ____federation_registration_endpoint:         '.*',
            ti_features_supported:                        "${json-unit.ignore}"
          }
    """
    And TGR current response at "$.body.body.metadata.openid_provider.ti_features_supported" matches as JSON:
    """
          {
            id_token_version_supported:      ["1.0.0","2.0.0"]
          }
    """
    And TGR current response with attribute "$.body.body.metadata.openid_provider.keywords.0" matches ".*product_type_version:.*4.0.0.*"
    And TGR current response with attribute "$.body.body.metadata.openid_provider.keywords.1" matches ".*product_type:.*PDT73.*"

  @TCID:IDPSEKTORAL_ENTITY_STATEMENT_006
  @Approval
  @PRIO:1
  @TESTSTUFE:4
  Scenario: IdpSektoral EntityStatement - Gutfall - Validiere JWKS in Body Claims

  ```
  Wir rufen das EntityStatement beim IdpSektoral ab

  Der Response Body muss ein JWS mit einem JWKS Claim sein.
  Das JWKS muss mindestens einen strukturell korrekten JWK mit use = sig enthalten.

    Given TGR clear recorded messages
    When TGR sende eine leere GET Anfrage an "${gsi.fachdienstEntityStatementEndpoint}"
    And TGR find first request to path ".*/.well-known/openid-federation"
    Then TGR current response at "$.body.body.jwks.keys.[?(@.kid.content =='${gsi.sigKeyKid}')]" matches as JSON:
        """
          {
            use:                           'sig',
            kid:                           '.*',
            kty:                           'EC',
            crv:                           'P-256',
            x:                             "${json-unit.ignore}",
            y:                             "${json-unit.ignore}"
          }
        """


  @TCID:IDPSEKTORAL_ENTITY_STATEMENT_007
  @Approval
  @PRIO:1
  @TESTSTUFE:4
  Scenario: IdpSektoral EntityStatement - Gutfall - Validiere scopes_supported und claims_supported

  ```
  Wir rufen das EntityStatement beim IdpSektoral ab

  In dem Claim scopes_supported müssen (neben möglichen anderen) die von der gematik vorgeschriebenen Scopes enthalten sein.
  In dem Claim claims_supported müssen (neben möglichen anderen) die von der gematik vorgeschriebenen Claims enthalten sein.

    Given TGR clear recorded messages
    When TGR sende eine leere GET Anfrage an "${gsi.fachdienstEntityStatementEndpoint}"
    And TGR find first request to path ".*/.well-known/openid-federation"
    And TGR current response with attribute "$.body.body.metadata.openid_provider.scopes_supported" matches ".*urn:telematik:given_name.*"
    And TGR current response with attribute "$.body.body.metadata.openid_provider.scopes_supported" matches ".*urn:telematik:geburtsdatum.*"
    And TGR current response with attribute "$.body.body.metadata.openid_provider.scopes_supported" matches ".*urn:telematik:alter.*"
    And TGR current response with attribute "$.body.body.metadata.openid_provider.scopes_supported" matches ".*urn:telematik:display_name.*"
    And TGR current response with attribute "$.body.body.metadata.openid_provider.scopes_supported" matches ".*urn:telematik:geschlecht.*"
    And TGR current response with attribute "$.body.body.metadata.openid_provider.scopes_supported" matches ".*urn:telematik:email.*"
    And TGR current response with attribute "$.body.body.metadata.openid_provider.scopes_supported" matches ".*urn:telematik:versicherter.*"
    And TGR current response with attribute "$.body.body.metadata.openid_provider.scopes_supported" matches ".*openid.*"
    And TGR current response with attribute "$.body.body.metadata.openid_provider.scopes_supported" matches ".*urn:telematik:family_name.*"
    And TGR current response with attribute "$.body.body.metadata.openid_provider.claims_supported" matches ".*urn:telematik:claims:given_name.*"
    And TGR current response with attribute "$.body.body.metadata.openid_provider.claims_supported" matches ".*birthdate.*"
    And TGR current response with attribute "$.body.body.metadata.openid_provider.claims_supported" matches ".*urn:telematik:claims:alter.*"
    And TGR current response with attribute "$.body.body.metadata.openid_provider.claims_supported" matches ".*urn:telematik:claims:display_name.*"
    And TGR current response with attribute "$.body.body.metadata.openid_provider.claims_supported" matches ".*urn:telematik:claims:geschlecht.*"
    And TGR current response with attribute "$.body.body.metadata.openid_provider.claims_supported" matches ".*urn:telematik:claims:email.*"
    And TGR current response with attribute "$.body.body.metadata.openid_provider.claims_supported" matches ".*urn:telematik:claims:profession.*"
    And TGR current response with attribute "$.body.body.metadata.openid_provider.claims_supported" matches ".*urn:telematik:claims:organization.*"
    And TGR current response with attribute "$.body.body.metadata.openid_provider.claims_supported" matches ".*urn:telematik:claims:id.*"
    And TGR current response with attribute "$.body.body.metadata.openid_provider.claims_supported" matches ".*urn:telematik:claims:family_name.*"


  @TCID:IDPSEKTORAL_ENTITY_STATEMENT_008
  @Approval
  @PRIO:1
  @TESTSTUFE:4
  Scenario: IdpSektoral EntityStatement - Gutfall - Validiere response_types_supported

  ```
  Wir rufen das EntityStatement beim IdpSektoral ab

  In dem Claim response_types_supported muss (neben möglichen anderen) der Wert "code" enthalten sein

    Given TGR clear recorded messages
    When TGR sende eine leere GET Anfrage an "${gsi.fachdienstEntityStatementEndpoint}"
    And TGR find first request to path ".*/.well-known/openid-federation"
    And TGR current response with attribute "$.body.body.metadata.openid_provider.response_types_supported" matches ".*code.*"


  @TCID:IDPSEKTORAL_ENTITY_STATEMENT_009
  @Approval
  @PRIO:1
  @TESTSTUFE:4
  Scenario: IdpSektoral EntityStatement - Gutfall - Validiere maximale zeitliche Gültigkeit

  ```
  Wir rufen das EntityStatement beim IdpSektoral ab. Die zeitliche Gültigkeit darf maximal 24 Stunden betragen. Es gibt
  keine vorgeschriebene Schranke für die minimale Gültigkeit, daher sind da die 60 Sekunden nicht verbindlich.



    Given TGR clear recorded messages
    When TGR sende eine leere GET Anfrage an "${gsi.fachdienstEntityStatementEndpoint}"
    And TGR find first request to path ".*/.well-known/openid-federation"
    Then TGR set local variable "entity_statement" to "!{rbel:currentResponseAsString('$.body')}"
    Then The JWT "${entity_statement}" is valid for more than 60 but less than 86400 seconds