# Release 3.0.14

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

