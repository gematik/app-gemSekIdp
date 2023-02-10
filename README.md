## Overview

Project **gemSekIdp-global** consists of 2 subprojects. These are:

* **gsi-server:** "gematik sektoraler IDP" - MVP of a sectoral IDP, used to develop/test the gsi-testsuite
* **gsi-testsuite:** Approval test suite (Zulassungstests) for sectoral IDPs

  <br>

### Configure, build and test

To quickly check your build environment just do in project root:

`mvn clean verify`

This command

- will build server and execute unit tests(disable: `mvn clean verify -Dskip.unittests`)
- will build testsuite and execute its integration tests (tiger framework) (
  disable: `mvn clean verify -Dskip.inttests`) <br>
  (gsi-testsuite/tiger.yaml is used as default TIGER_TESTENV_CFGFILE)
  <br>
  A default test filter is set in pom (`<cucumber.filter.tags>`), so don't care.
  <br>
  All tests in serenity report should be passed.

#### Serenity BDD Report

- find your generated report (at the end of integration tests)
  here:  [gsi-testsuite/target/site/serenity/index.html](gsi-testsuite/target/site/serenity/index.html)

### Test an external sectoral IDP (e.g. your own server)

- To check test environment, the gsi-server can be used. Just build/start this server and
  execute [runTestsuite-external-Idp.sh](runTestsuite-external-Idp.sh).
- The address of the SUT (system under test == sectoral IDP server) is configured
  in [gsi-testsuite/tiger-external-Idp.yaml](gsi-testsuite/tiger-external-Idp.yaml). Local gsi-server is set as default.
