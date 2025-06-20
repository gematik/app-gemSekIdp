# Release 8.1.0

- refactor setting/printing log level - see [gsi-server logging](README.md#gsi-server logging)
- add test case to verify the issuer of the token signing key
- remove relaxedHTTPSValidation
- skip docker build as default
- add bde logging, disabled by default
- handle unknown KVNR by throwing GSI-Exception instead of using a fallback
- adapt management section in configuration to Spring Boot version >= 3.2
- handle invalid signature of entity statement with error response 400
- add claim ti_features_supported to openid_provider in entity_statement
- remove dependency spring-boot-starter-jersey (CVE-2025-48988)
- update dependencies

# Release 8.0.0

- remove static host name resolving
- change exp time of entity statement to 2 hours 
- remove token signing key from jwks in entity statement
- add openid provider to metadata of idp entity statement
- add metadata to EntityStatementAboutRp, validate PAR parameters against EntityStatementAboutRp
- fail fast if clientID is not registered at fedmaster
- change token signing certificate
- disable certificate validation in testsuite and remove tiger proxy for invalid client certificate
- add cert rotation test to idpsektoralPushedAuthorizationEndpoint.feature
- add claims for selection to landing page
- update dependencies

# Release 7.1.0

- add x5c element to signature-header of idtoken
- improve validation when missing essential claims
- add validation for redirect uri
- add test identities
- update dependencies


# Release 7.0.6

- fix expiry date validation of entity statement (fixes caching issue)
- adapt server and testsuite to set/expect amr as array
- add test identities
- update dependencies

# Release 7.0.4

- add documentation for key rotation
- allow multiple tls certs in entity statement for key rotation
- refactoring of EntityStatementRpService into separate services
- add test identities
- add validation for optional claims parameter in par endpoint
- update configuration: mTLS at par endpoint now required for gsi.dev and gsi-ref.dev
- update dependencies

# Release 7.0.3

- skip jacoco by default
- add documentation

# Release 7.0.2

- Java 21
- switch to docker base image eclipse-temurin:21-jre
- made jmdns dependant on active mdns Spring profile
- introduce static host name resolving dependent on active hostsmap Spring profile
- add optional parameter amr in par request
- set request_uri as configuration property instead of constant
- add mTLS configuration for par and token endpoint
- add client cert validation
- add parameters in metadata of entity statement
- add dependency for openapi documentation
- update dependencies

# Release 6.0.0

- add new maven module gsi-fedmaster
- remove parent pom from testsuite to avoid dependency conflicts
- refactor names: distinguish between relying party and identity provider
- add scripts to start a local federation
- rename keys
- add static qr code to GSIA (Android app) latest version download
- update dependencies

# Release 5.0.3

- refactor key handling, use PrivateKey instead of p12 container when certificate is not required
- add testcase
- switch to docker base image eclipse-temurin:17-jre
- rename docker image
- update dependencies

# Release 4.0.1

-add test identities

# Release 4.0.0

- add controllers for assetlinks files
- AuthenticationService binds user to session, reads userData from file selected by KVNR
- refactor session storage (from list 2 map), delete sessions after token delivery, limit session amount
- add key to decrypt id_token in testsuite
- update dependencies

# Release 3.0.5

- minor refactoring/some bug fixes in testsuite

# Release 3.0.4

- fix missing iat and iss in signedJwks structure

# Release 3.0.2

- structure of signed Jwks of relying party fixed
- add debug logging
- update dependencies

# Release 3.0.1

- add key for idToken signature to JWKS
- read key from entity statement by keyId
- update dependencies
- fix expected location of jwks in entity statements of relying parties
- set claims depending on requested scopes
- in testsuite ignore charset of entity statement
- add Web-App Flow (2 devices), landing page template with thymeleaf

# Release 2.0.2

- fix entity statement for gsi.dev.gematik.solutions
- fix user data claims in ID-TOKEN
- encryption of ID_TOKEN implemented
- set log level for some packages as JVM property
- several fixes in testsuite

# Release 1.3.6

- update dependencies
- refactor services
- refactor license header

# Release 1.3.5

- deployment to https://gsi.dev.gematik.solutions

# Release 1.3.3

- update tiger
- add tests
- fix bugs
- refactoring

# Release 1.3.1

- add documentation

# Release 1.3.0

### gsi-server

- implement autoregistration
- improved error handling

### gsi-testsuite

- add test cases for signed jwks
- add test cases for id_token
- various minor improvements/bug fixes
- test cases for token endpoint still under construction

# Release 1.1.0

### gsi-testsuite

- test cases for pushed authorization requests

# Release 1.0.0

### gsi-server

- get server addresses from configuration

# Release 0.1.2

### gsi-server

- delivers entity statement
- work on additional functionalities already in progress

### gsi-testsuite

- test cases to fetch and inspect an entity statement of a sectoral IDP

