## Overview

Project **gemSekIdp-global** consists of 2 subprojects. These are:

* **gsi-server:** "gematik sektoraler IDP" - MVP of a sectoral IDP, used to develop/test the gsi-testsuite
* **gsi-testsuite:** Approval test suite (Zulassungstests) for sectoral IDPs

  <br>

### build project and run unit tests

To quickly check your build environment just do in project root:

`mvn clean package`

This command

- will build server and testsuite and execute unit tests(disable: `mvn clean package -Dskip.unittests`)
- in order to run the integration tests (= testsuite) follow the instruction listed under "Test an external sectoral
  IDP"

### Test an external sectoral IDP (e.g. your own server)

- To check test environment, the gsi-server can be used. Just build/start this server and
  execute [runTestsuite-external-Idp.sh](runTestsuite-external-Idp.sh).
- The address of the SUT (system under test == sectoral IDP server) is configured
  in [gsi-testsuite/tiger-external-Idp.yaml](gsi-testsuite/tiger-external-Idp.yaml). Local gsi-server is set as default.
- In order to validate the structure of an ID_TOKEN one has to add its value (base64 encoded) to the tc_properties-file
  that is used during the test execution

#### Serenity BDD Report

- find your generated report (at the end of integration tests)
  here:  [gsi-testsuite/target/site/serenity/index.html](gsi-testsuite/target/site/serenity/index.html)
