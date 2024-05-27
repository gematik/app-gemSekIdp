## Overview

Project **gemSekIdp-global** consists of 2 subprojects. These are:

* **gsi-server:** "gematik sektoraler IDP" - MVP of a sectoral IDP, used to develop/test the gsi-testsuite
* **gsi-testsuite:** Approval test suite (Zulassungstests) for sectoral IDPs, will be executed as integration tests

  <br>

### just build project

To quickly check your build environment without running any tests (just build idp sektoral server and testsuite) do in
project root:

`mvn clean package -Dskip.unittests`

### build project and run unit tests (skip integration tests == skip testsuite execution)

`mvn clean test -Dskip.inttests`

### build project and run integration tests (unit tests will be executed as well as long as they are not skipped)

To execute integration tests you have to set the environment variable where the tiger test framework find its configuration:

`export TIGER_TESTENV_CFGFILE=tiger-external-Idp.yaml`
`mvn test`

In order to run the integration tests (= testsuite) follow the instruction listed under "Test an external sectoral IDP".

The keys
`gsi-fedmaster/src/main/resources/keys/ref-fedmaster-sig-privkey.pem`
`gsi-server/src/main/resources/keys/ref-gsi-sig-privkey.pem`
are added for unit tests only and can be published.

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

### run gsi-server locally

- check entity statement:
  `curl http://localhost:8085/.well-known/openid-federation`
  will produce a jwt like this:

> **_entity statement:_** `
eyJhbGciOiJFUzI1NiIsInR5cCI6ImVudGl0eS1zdGF0ZW1lbnQrand0Iiwia2lkIjoicHVrX2lkcF9zaWcifQ.eyJpc3MiOiJodHRwczovL2dzaS5kZXYuZ2VtYXRpay5zb2x1dGlvbnMiLCJzdWIiOiJodHRwczovL2dzaS5kZXYuZ2VtYXRpay5zb2x1dGlvbnMiLCJpYXQiOjE3MDY3OTA1MjEsImV4cCI6MTcwNzM5NTMyMSwiandrcyI6eyJrZXlzIjpbeyJ1c2UiOiJzaWciLCJraWQiOiJwdWtfaWRwX3NpZyIsImt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiTXE5MzNGVF9WOHhkMVRrZkIwcEgwMmQ2Y3gyYm1VUy1ieEh1QnRBMXlmcyIsInkiOiI1dXdmOHBoVWJXSWk5MkNxZ2dsTTk0ZnQtRkM0TUhIODM2a2hzd282cHBvIiwiYWxnIjoiRVMyNTYifSx7InVzZSI6InNpZyIsImtpZCI6InB1a19mZWRfaWRwX3Rva2VuIiwia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJNcTkzM0ZUX1Y4eGQxVGtmQjBwSDAyZDZjeDJibVVTLWJ4SHVCdEExeWZzIiwieSI6IjV1d2Y4cGhVYldJaTkyQ3FnZ2xNOTRmdC1GQzRNSEg4MzZraHN3bzZwcG8iLCJhbGciOiJFUzI1NiJ9XX0sImF1dGhvcml0eV9oaW50cyI6WyJodHRwczovL2FwcC10ZXN0LmZlZGVyYXRpb25tYXN0ZXIuZGUiXSwibWV0YWRhdGEiOnsib3BlbmlkX3Byb3ZpZGVyIjp7Imlzc3VlciI6Imh0dHBzOi8vZ3NpLmRldi5nZW1hdGlrLnNvbHV0aW9ucyIsInNpZ25lZF9qd2tzX3VyaSI6Imh0dHBzOi8vZ3NpLmRldi5nZW1hdGlrLnNvbHV0aW9ucy9qd3MuanNvbiIsIm9yZ2FuaXphdGlvbl9uYW1lIjoiZ2VtYXRpayBzZWt0b3JhbGVyIElEUCIsImxvZ29fdXJpIjoiaHR0cHM6Ly9nc2kuZGV2LmdlbWF0aWsuc29sdXRpb25zL25vTG9nb1lldCIsImF1dGhvcml6YXRpb25fZW5kcG9pbnQiOiJodHRwczovL2dzaS5kZXYuZ2VtYXRpay5zb2x1dGlvbnMvYXV0aCIsInRva2VuX2VuZHBvaW50IjoiaHR0cHM6Ly9nc2kuZGV2LmdlbWF0aWsuc29sdXRpb25zL3Rva2VuIiwicHVzaGVkX2F1dGhvcml6YXRpb25fcmVxdWVzdF9lbmRwb2ludCI6Imh0dHBzOi8vZ3NpLmRldi5nZW1hdGlrLnNvbHV0aW9ucy9QQVJfQXV0aCIsImNsaWVudF9yZWdpc3RyYXRpb25fdHlwZXNfc3VwcG9ydGVkIjpbImF1dG9tYXRpYyJdLCJzdWJqZWN0X3R5cGVzX3N1cHBvcnRlZCI6WyJwYWlyd2lzZSJdLCJyZXNwb25zZV90eXBlc19zdXBwb3J0ZWQiOlsiY29kZSJdLCJzY29wZXNfc3VwcG9ydGVkIjpbInVybjp0ZWxlbWF0aWs6Z2VzY2hsZWNodCIsIm9wZW5pZCIsInVybjp0ZWxlbWF0aWs6ZGlzcGxheV9uYW1lIiwidXJuOnRlbGVtYXRpazp2ZXJzaWNoZXJ0ZXIiLCJ1cm46dGVsZW1hdGlrOmVtYWlsIiwidXJuOnRlbGVtYXRpazphbHRlciIsInVybjp0ZWxlbWF0aWs6Z2VidXJ0c2RhdHVtIiwidXJuOnRlbGVtYXRpazpnaXZlbl9uYW1lIl0sInJlc3BvbnNlX21vZGVzX3N1cHBvcnRlZCI6WyJxdWVyeSJdLCJncmFudF90eXBlc19zdXBwb3J0ZWQiOlsiYXV0aG9yaXphdGlvbl9jb2RlIl0sInJlcXVpcmVfcHVzaGVkX2F1dGhvcml6YXRpb25fcmVxdWVzdHMiOnRydWUsInRva2VuX2VuZHBvaW50X2F1dGhfbWV0aG9kc19zdXBwb3J0ZWQiOlsic2VsZl9zaWduZWRfdGxzX2NsaWVudF9hdXRoIl0sInJlcXVlc3RfYXV0aGVudGljYXRpb25fbWV0aG9kc19zdXBwb3J0ZWQiOnsiYXIiOlsibm9uZSJdLCJwYXIiOlsic2VsZl9zaWduZWRfdGxzX2NsaWVudF9hdXRoIl19LCJpZF90b2tlbl9zaWduaW5nX2FsZ192YWx1ZXNfc3VwcG9ydGVkIjpbIkVTMjU2Il0sImlkX3Rva2VuX2VuY3J5cHRpb25fYWxnX3ZhbHVlc19zdXBwb3J0ZWQiOlsiRUNESC1FUyJdLCJpZF90b2tlbl9lbmNyeXB0aW9uX2VuY192YWx1ZXNfc3VwcG9ydGVkIjpbIkEyNTZHQ00iXSwidXNlcl90eXBlX3N1cHBvcnRlZCI6WyJJUCJdfSwiZmVkZXJhdGlvbl9lbnRpdHkiOnsibmFtZSI6ImdlbWF0aWsgc2VrdG9yYWxlciBJRFAiLCJjb250YWN0cyI6WyJzdXBwb3J0QGlkcDQ3MTEuZGUiLCJpZG1AZ2VtYXRpay5kZSJdLCJob21lcGFnZV91cmkiOiJodHRwczovL2lkcDQ3MTEuZGUifX19.RLW70R4rsmf_4m98pJIDpEWaKImK3QKv2MBRGiL8ImREJv_8srz-niYe5ObxMAJ4mOw1cy3OYkWaDfyY-eeMnw`

Copy this jwt to the clipboard and paste it www.jwt.io to see the content.

### run federation locally

Start a local federation consisting of a Fedmaster and an IDP server. Both are modules inside this maven project.
You have to configure two things:

1. The Authorization Server must be registerd in the federation. This is done by configuring the Authorization server in the fedmaster's configuration file:
   gsi-fedmaster/src/main/resources/application.yml (section `relyingPartyConfigs`)
2. Configure the servers to be started in `federation/startFederationLocal.sh` but
   ootb the federation should start without any further configuration.

The federation can be build and started then by executing this script:

```shell
./federation/startFederationLocalJars.sh
```

##### fedmaster

```shell
# get entity statement
curl http://localhost:8083/.well-known/openid-federation
```

```shell
# get federation list and idp list
curl http://localhost:8083/federation_list
curl http://localhost:8083/.well-known/idp_list
```

```shell
# get entity statement about gsi-server 
curl 'http://127.0.0.1:8083/federation_fetch_endpoint?sub=http://127.0.0.1:8085&iss=http://127.0.0.1:8083'
# get entity statement about gra-server
curl 'http://127.0.0.1:8083/federation_fetch_endpoint?sub=http://127.0.0.1:8084&iss=http://127.0.0.1:8083'
```

##### gra-server

```shell
# get entity statement
curl http://localhost:8084/.well-known/openid-federation
```

##### gsi-server

```shell
# get entity statement
curl http://localhost:8085/.well-known/openid-federation
```

send PAR request to gsi-server
expected is a HTTP 201 mit Content-Type: application/json with the redirect_uri
like: `{"request_uri":"urn:http://127.0.0.1:8084:48ac8294c7ef112d","expires_in":90}`

```shell
curl --location --request POST 'http://127.0.0.1:8085/PAR_Auth?scope=urn%3Atelematik%3Adisplay_name%20urn%3Atelematik%3Aversicherter%20openid&acr_values=gematik-ehealth-loa-high&response_type=code&state=yyystateyyy&redirect_uri=https%3A%2F%2Fredirect.testsuite.gsi&code_challenge_method=S256&nonce=vy7rM801AQw1or22GhrZ&client_id=http%3A%2F%2F127.0.0.1%3A8084&code_challenge=9tI-0CQIkUYaGQOVR1emznlDFjlX0kVY1yd3oiMtGUI' \
--header 'AcceptAccept: */*' \
--header 'Content-Type: application/x-www-form-urlencoded; charset=UTF-8'
```

send authorization request to auth endpoint of auth-server

```shell
curl --location 'http://127.0.0.1:8084/auth?client_id=e42RezeptApp&state=mystate&redirect_uri=anyUri&code_challenge=P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk&code_challenge_method=S256&response_type=code&scope=e-rezept&idp_iss=http%3A%2F%2F127.0.0.1%3A8085'
```
