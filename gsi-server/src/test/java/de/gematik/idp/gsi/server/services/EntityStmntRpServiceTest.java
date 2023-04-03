/*
 * Copyright (c) 2023 gematik GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an 'AS IS' BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.idp.gsi.server.services;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

import de.gematik.idp.IdpConstants;
import de.gematik.idp.crypto.CryptoLoader;
import de.gematik.idp.exceptions.IdpJwtExpiredException;
import de.gematik.idp.gsi.server.configuration.GsiConfiguration;
import de.gematik.idp.gsi.server.exceptions.GsiException;
import java.io.File;
import java.io.IOException;
import java.security.PublicKey;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.mockserver.client.MockServerClient;
import org.mockserver.model.MediaType;
import org.mockserver.springtest.MockServerTest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

@Slf4j
@MockServerTest("server.url=http://localhost:${mockServerPort}")
@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class EntityStmntRpServiceTest {

  @Value("${server.url}")
  private String mockServerUrl;

  private MockServerClient mockServerClient;
  @Autowired EntityStmntRpService entityStmntRpService;
  @Autowired GsiConfiguration gsiConfiguration;

  private final String ENTITY_STMNT_IDP_FACHDIENST_EXPIRED =
      "eyJhbGciOiJFUzI1NiIsInR5cCI6ImVudGl0eS1zdGF0ZW1lbnQrand0Iiwia2lkIjoicHVrX2ZhY2hkaWVuc3Rfc2lnIn0.eyJpc3MiOiJodHRwOi8vZ3NsdHVjZDAxLmx0dS5pbnQuZ2VtYXRpay5kZTo0MDE1Iiwic3ViIjoiaHR0cDovL2dzbHR1Y2QwMS5sdHUuaW50LmdlbWF0aWsuZGU6NDAxNSIsImlhdCI6MTY3ODM1NjM5OSwiZXhwIjoxNjc4NDQyNzk5LCJqd2tzIjp7ImtleXMiOlt7InVzZSI6InNpZyIsImtpZCI6InB1a19mYWNoZGllbnN0X3NpZyIsImt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiOWJKczI3WUFmbE1VV0s1bnh1aUY2WEFHMEphenV2d1JpMUVwRkswWEtpayIsInkiOiJQOGx6TlZST2dUdXdiRHFzZDhyVDFBSTN6ZXo5NEhCc1REcE92YWpQMHJZIn1dfSwiYXV0aG9yaXR5X2hpbnRzIjpbImh0dHA6Ly9nc2x0dWNkMDEubHR1LmludC5nZW1hdGlrLmRlOjQwMTQiXSwibWV0YWRhdGEiOnsib3BlbmlkX3JlbHlpbmdfcGFydHkiOnsic2lnbmVkX2p3a3NfdXJpIjoiaHR0cDovL2dzbHR1Y2QwMS5sdHUuaW50LmdlbWF0aWsuZGU6NDAxNS9qd3MuanNvbiIsIm9yZ2FuaXphdGlvbl9uYW1lIjoiRmFjaGRpZW5zdDAwNyBkZXMgRmVkSWRwIFBPQ3MiLCJjbGllbnRfbmFtZSI6IkZhY2hkaWVuc3QwMDciLCJsb2dvX3VyaSI6Imh0dHA6Ly9nc2x0dWNkMDEubHR1LmludC5nZW1hdGlrLmRlOjQwMTUvbm9Mb2dvWWV0IiwicmVkaXJlY3RfdXJpcyI6WyJodHRwczovL0ZhY2hkaWVuc3QwMDcuZGUvY2xpZW50IiwiaHR0cHM6Ly9yZWRpcmVjdC50ZXN0c3VpdGUuZ3NpIl0sInJlc3BvbnNlX3R5cGVzIjpbImNvZGUiXSwiY2xpZW50X3JlZ2lzdHJhdGlvbl90eXBlcyI6WyJhdXRvbWF0aWMiXSwiZ3JhbnRfdHlwZXMiOlsiYXV0aG9yaXphdGlvbl9jb2RlIl0sInJlcXVpcmVfcHVzaGVkX2F1dGhvcml6YXRpb25fcmVxdWVzdHMiOnRydWUsInRva2VuX2VuZHBvaW50X2F1dGhfbWV0aG9kIjoicHJpdmF0ZV9rZXlfand0IiwiZGVmYXVsdF9hY3JfdmFsdWVzIjoiZ2VtYXRpay1laGVhbHRoLWxvYS1oaWdoIiwiaWRfdG9rZW5fc2lnbmVkX3Jlc3BvbnNlX2FsZyI6IkVTMjU2IiwiaWRfdG9rZW5fZW5jcnlwdGVkX3Jlc3BvbnNlX2FsZyI6IkVDREgtRVMiLCJpZF90b2tlbl9lbmNyeXB0ZWRfcmVzcG9uc2VfZW5jIjoiQTI1NkdDTSIsInNjb3BlIjoidXJuOnRlbGVtYXRpazpkaXNwbGF5X25hbWUgdXJuOnRlbGVtYXRpazp2ZXJzaWNoZXJ0ZXIgb3BlbmlkIn0sImZlZGVyYXRpb25fZW50aXR5Ijp7Im5hbWUiOiJGYWNoZGllbnN0MDA3IiwiY29udGFjdHMiOiJTdXBwb3J0QEZhY2hkaWVuc3QwMDcuZGUiLCJob21lcGFnZV91cmkiOiJodHRwczovL0ZhY2hkaWVuc3QwMDcuZGUifX19.sJ0XjEEs-VL0kupnZgWEFgAN0OXGQgMIRPwlXgqa1TWh_OGbbFbuE-nIlrgFkc6mqBXVS9imeVZFs6-3_NtiTA";
  //  private final String FEDERATION_LIST =
  //      "[\"http://idp-fachdienst:8084\",\"http://idp-sektoral:8082\"]";

  private final String ENTITY_STMNT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2043 =
      "eyJhbGciOiJFUzI1NiIsInR5cCI6ImVudGl0eS1zdGF0ZW1lbnQrand0Iiwia2lkIjoicHVrX2ZhY2hkaWVuc3Rfc2lnIn0.eyJpc3MiOiJodHRwczovL2lkcGZhZGkuZGV2LmdlbWF0aWsuc29sdXRpb25zIiwic3ViIjoiaHR0cHM6Ly9pZHBmYWRpLmRldi5nZW1hdGlrLnNvbHV0aW9ucyIsImlhdCI6MTY3OTU2NTMzMCwiZXhwIjoyMzEwMjg1MzMwLCJqd2tzIjp7ImtleXMiOlt7InVzZSI6InNpZyIsImtpZCI6InB1a19mYWNoZGllbnN0X3NpZyIsImt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiOWJKczI3WUFmbE1VV0s1bnh1aUY2WEFHMEphenV2d1JpMUVwRkswWEtpayIsInkiOiJQOGx6TlZST2dUdXdiRHFzZDhyVDFBSTN6ZXo5NEhCc1REcE92YWpQMHJZIn1dfSwiYXV0aG9yaXR5X2hpbnRzIjpbImh0dHBzOi8vaWRwLWZlZG1hc3Rlci1ycHUucmlzZWRldi5hdCJdLCJtZXRhZGF0YSI6eyJvcGVuaWRfcmVseWluZ19wYXJ0eSI6eyJzaWduZWRfandrc191cmkiOiJodHRwczovL2lkcGZhZGkuZGV2LmdlbWF0aWsuc29sdXRpb25zL2p3cy5qc29uIiwib3JnYW5pemF0aW9uX25hbWUiOiJGYWNoZGllbnN0MDA3IGRlcyBGZWRJZHAgUE9DcyIsImNsaWVudF9uYW1lIjoiRmFjaGRpZW5zdDAwNyIsImxvZ29fdXJpIjoiaHR0cHM6Ly9pZHBmYWRpLmRldi5nZW1hdGlrLnNvbHV0aW9ucy9ub0xvZ29ZZXQiLCJyZWRpcmVjdF91cmlzIjpbImh0dHBzOi8vRmFjaGRpZW5zdDAwNy5kZS9jbGllbnQiLCJodHRwczovL3JlZGlyZWN0LnRlc3RzdWl0ZS5nc2kiXSwicmVzcG9uc2VfdHlwZXMiOlsiY29kZSJdLCJjbGllbnRfcmVnaXN0cmF0aW9uX3R5cGVzIjpbImF1dG9tYXRpYyJdLCJncmFudF90eXBlcyI6WyJhdXRob3JpemF0aW9uX2NvZGUiXSwicmVxdWlyZV9wdXNoZWRfYXV0aG9yaXphdGlvbl9yZXF1ZXN0cyI6dHJ1ZSwidG9rZW5fZW5kcG9pbnRfYXV0aF9tZXRob2QiOiJwcml2YXRlX2tleV9qd3QiLCJkZWZhdWx0X2Fjcl92YWx1ZXMiOiJnZW1hdGlrLWVoZWFsdGgtbG9hLWhpZ2giLCJpZF90b2tlbl9zaWduZWRfcmVzcG9uc2VfYWxnIjoiRVMyNTYiLCJpZF90b2tlbl9lbmNyeXB0ZWRfcmVzcG9uc2VfYWxnIjoiRUNESC1FUyIsImlkX3Rva2VuX2VuY3J5cHRlZF9yZXNwb25zZV9lbmMiOiJBMjU2R0NNIiwic2NvcGUiOiJ1cm46dGVsZW1hdGlrOmRpc3BsYXlfbmFtZSB1cm46dGVsZW1hdGlrOnZlcnNpY2hlcnRlciBvcGVuaWQifSwiZmVkZXJhdGlvbl9lbnRpdHkiOnsibmFtZSI6IkZhY2hkaWVuc3QwMDciLCJjb250YWN0cyI6IlN1cHBvcnRARmFjaGRpZW5zdDAwNy5kZSIsImhvbWVwYWdlX3VyaSI6Imh0dHBzOi8vRmFjaGRpZW5zdDAwNy5kZSJ9fX0.pdNCBhrNw4lU9Uewg1l8nHUS0xvJDM5kxogiBhmcdvxguzlggWPd_hLz4DtS5ITQFL-othO6oLC7MBqziH3wtw";
  /*
  http://idp-fachdienst:8084 is part of this saved entity statement
   */
  private final String ENTITY_STMNT_ABOUT_IDP_FACHDIENST_EXPIRED =
      "eyJhbGciOiJFUzI1NiIsInR5cCI6ImVudGl0eS1zdGF0ZW1lbnQrand0Iiwia2lkIjoicHVrX2ZlZF9zaWcifQ.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODMiLCJzdWIiOiJodHRwOi8vaWRwLWZhY2hkaWVuc3Q6ODA4NCIsImF1ZCI6bnVsbCwiaWF0IjoxNjc4MzY1MDEzLCJleHAiOjE2Nzg5Njk4MTMsImp3a3MiOnsia2V5cyI6W3sidXNlIjoic2lnIiwia2lkIjoicHVrX2ZkX3NpZyIsImt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiOWJKczI3WUFmbE1VV0s1bnh1aUY2WEFHMEphenV2d1JpMUVwRkswWEtpayIsInkiOiJQOGx6TlZST2dUdXdiRHFzZDhyVDFBSTN6ZXo5NEhCc1REcE92YWpQMHJZIn1dfX0.a--3gFnZPesHcdkwG3EH2uu7bf-GlGLUkWGwoNaWU-H8vDDDrWTWKervDFPbXJUVmPadXOTsoSJQW8bMPuQP5A";

  private final String ENTITY_STMNT_ABOUT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2043 =
      "eyJhbGciOiJFUzI1NiIsInR5cCI6ImVudGl0eS1zdGF0ZW1lbnQrand0Iiwia2lkIjoicHVrX2ZlZF9zaWcifQ.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjU3OTAyIiwic3ViIjoiaHR0cDovLzEyNy4wLjAuMTo4MDg0IiwiYXVkIjpudWxsLCJpYXQiOjE2Nzk1NzE4NTYsImV4cCI6MjMxMDI5MTg1NiwiandrcyI6eyJrZXlzIjpbeyJ1c2UiOiJzaWciLCJraWQiOiJwdWtfZmRfc2lnIiwia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiI5YkpzMjdZQWZsTVVXSzVueHVpRjZYQUcwSmF6dXZ3UmkxRXBGSzBYS2lrIiwieSI6IlA4bHpOVlJPZ1R1d2JEcXNkOHJUMUFJM3plejk0SEJzVERwT3ZhalAwclkifV19fQ.QQN5-IcTdmxg8PT5BlLT7OLlATLBI1PVFvods8dVCBd_b7m6sEOi8Y1GJp2hk08MoQatLbTvMTSVv5lqeH59hQ";

  @Test
  void getEntityStatementRp() {
    mockServerClient
        .when(request().withMethod("GET").withPath(IdpConstants.ENTITY_STATEMENT_ENDPOINT))
        .respond(
            response()
                .withStatusCode(200)
                .withContentType(MediaType.APPLICATION_JSON)
                .withBody(ENTITY_STMNT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2043));
    mockServerClient
        .when(
            request().withMethod("GET").withPath(IdpConstants.FEDMASTER_FEDERATION_FETCH_ENDPOINT))
        .respond(
            response()
                .withStatusCode(200)
                .withContentType(MediaType.APPLICATION_JSON)
                .withBody(ENTITY_STMNT_ABOUT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2043));
    gsiConfiguration.setFedmasterUrl(mockServerUrl);
    final String entStmntFd = entityStmntRpService.getEntityStatementRp(mockServerUrl);
    assertThat(entStmntFd).isNotNull();
  }

  @Test
  void getEntityStatementAboutRp_Idpfachdienst() {
    mockServerClient
        .when(
            request().withMethod("GET").withPath(IdpConstants.FEDMASTER_FEDERATION_FETCH_ENDPOINT))
        .respond(
            response()
                .withStatusCode(200)
                .withContentType(MediaType.APPLICATION_JSON)
                .withBody(ENTITY_STMNT_ABOUT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2043));
    // switch configuration to mockserver
    gsiConfiguration.setFedmasterUrl(mockServerUrl);
    final String entityStmntAboutFachdienst =
        entityStmntRpService.getEntityStatementAboutRp("dummyUrl");
    assertThat(entityStmntAboutFachdienst).isNotNull();
    log.info(entityStmntAboutFachdienst);
  }

  @Test
  void doAutoregistration() {
    mockServerClient
        .when(request().withMethod("GET").withPath(IdpConstants.ENTITY_STATEMENT_ENDPOINT))
        .respond(
            response()
                .withStatusCode(200)
                .withContentType(MediaType.APPLICATION_JSON)
                .withBody(ENTITY_STMNT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2043));
    mockServerClient
        .when(
            request().withMethod("GET").withPath(IdpConstants.FEDMASTER_FEDERATION_FETCH_ENDPOINT))
        .respond(
            response()
                .withStatusCode(200)
                .withContentType(MediaType.APPLICATION_JSON)
                .withBody(ENTITY_STMNT_ABOUT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2043));
    gsiConfiguration.setFedmasterUrl(mockServerUrl);
    assertDoesNotThrow(() -> entityStmntRpService.doAutoregistration(mockServerUrl));
  }

  @Test
  void getRedirectUrisEntityStatementRp() {
    final String entStmntFd =
        "eyJhbGciOiJFUzI1NiIsInR5cCI6ImVudGl0eS1zdGF0ZW1lbnQrand0Iiwia2lkIjoicHVrX2ZhY2hkaWVuc3Rfc2lnIn0.eyJpc3MiOiJodHRwOi8vZ3NsdHVjZDAxLmx0dS5pbnQuZ2VtYXRpay5kZTo0MDE1Iiwic3ViIjoiaHR0cDovL2dzbHR1Y2QwMS5sdHUuaW50LmdlbWF0aWsuZGU6NDAxNSIsImlhdCI6MTY3OTA2OTYwOSwiZXhwIjoxNjc5MTU2MDA5LCJqd2tzIjp7ImtleXMiOlt7InVzZSI6InNpZyIsImtpZCI6InB1a19mYWNoZGllbnN0X3NpZyIsImt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiOWJKczI3WUFmbE1VV0s1bnh1aUY2WEFHMEphenV2d1JpMUVwRkswWEtpayIsInkiOiJQOGx6TlZST2dUdXdiRHFzZDhyVDFBSTN6ZXo5NEhCc1REcE92YWpQMHJZIn1dfSwiYXV0aG9yaXR5X2hpbnRzIjpbImh0dHA6Ly9nc2x0dWNkMDEubHR1LmludC5nZW1hdGlrLmRlOjQwMTQiXSwibWV0YWRhdGEiOnsib3BlbmlkX3JlbHlpbmdfcGFydHkiOnsic2lnbmVkX2p3a3NfdXJpIjoiaHR0cDovL2dzbHR1Y2QwMS5sdHUuaW50LmdlbWF0aWsuZGU6NDAxNS9qd3MuanNvbiIsIm9yZ2FuaXphdGlvbl9uYW1lIjoiRmFjaGRpZW5zdDAwNyBkZXMgRmVkSWRwIFBPQ3MiLCJjbGllbnRfbmFtZSI6IkZhY2hkaWVuc3QwMDciLCJsb2dvX3VyaSI6Imh0dHA6Ly9nc2x0dWNkMDEubHR1LmludC5nZW1hdGlrLmRlOjQwMTUvbm9Mb2dvWWV0IiwicmVkaXJlY3RfdXJpcyI6WyJodHRwczovL0ZhY2hkaWVuc3QwMDcuZGUvY2xpZW50IiwiaHR0cHM6Ly9yZWRpcmVjdC50ZXN0c3VpdGUuZ3NpIl0sInJlc3BvbnNlX3R5cGVzIjpbImNvZGUiXSwiY2xpZW50X3JlZ2lzdHJhdGlvbl90eXBlcyI6WyJhdXRvbWF0aWMiXSwiZ3JhbnRfdHlwZXMiOlsiYXV0aG9yaXphdGlvbl9jb2RlIl0sInJlcXVpcmVfcHVzaGVkX2F1dGhvcml6YXRpb25fcmVxdWVzdHMiOnRydWUsInRva2VuX2VuZHBvaW50X2F1dGhfbWV0aG9kIjoicHJpdmF0ZV9rZXlfand0IiwiZGVmYXVsdF9hY3JfdmFsdWVzIjoiZ2VtYXRpay1laGVhbHRoLWxvYS1oaWdoIiwiaWRfdG9rZW5fc2lnbmVkX3Jlc3BvbnNlX2FsZyI6IkVTMjU2IiwiaWRfdG9rZW5fZW5jcnlwdGVkX3Jlc3BvbnNlX2FsZyI6IkVDREgtRVMiLCJpZF90b2tlbl9lbmNyeXB0ZWRfcmVzcG9uc2VfZW5jIjoiQTI1NkdDTSIsInNjb3BlIjoidXJuOnRlbGVtYXRpazpkaXNwbGF5X25hbWUgdXJuOnRlbGVtYXRpazp2ZXJzaWNoZXJ0ZXIgb3BlbmlkIn0sImZlZGVyYXRpb25fZW50aXR5Ijp7Im5hbWUiOiJGYWNoZGllbnN0MDA3IiwiY29udGFjdHMiOiJTdXBwb3J0QEZhY2hkaWVuc3QwMDcuZGUiLCJob21lcGFnZV91cmkiOiJodHRwczovL0ZhY2hkaWVuc3QwMDcuZGUifX19.Is8Ag-3Z0DwWS7RXCSRDPy1_m3bZatBB12PFOmTa8cBw0WrzixE23VL6xFeBFAFowlez-QQKU_WRhyPkX18-wQ";
    final List<String> redirecturis =
        EntityStmntRpService.getRedirectUrisEntityStatementRp(entStmntFd);
    assertThat(redirecturis.size()).isEqualTo(2);
  }

  @Test
  void verifyRedirectUriExistsInEntityStmnt() {
    mockServerClient
        .when(request().withMethod("GET").withPath(IdpConstants.ENTITY_STATEMENT_ENDPOINT))
        .respond(
            response()
                .withStatusCode(200)
                .withContentType(MediaType.APPLICATION_JSON)
                .withBody(ENTITY_STMNT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2043));
    mockServerClient
        .when(
            request().withMethod("GET").withPath(IdpConstants.FEDMASTER_FEDERATION_FETCH_ENDPOINT))
        .respond(
            response()
                .withStatusCode(200)
                .withContentType(MediaType.APPLICATION_JSON)
                .withBody(ENTITY_STMNT_ABOUT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2043));
    gsiConfiguration.setFedmasterUrl(mockServerUrl);
    final String nonExistingUri = "nonExistingUri";
    assertThatThrownBy(
            () ->
                entityStmntRpService.verifyRedirectUriExistsInEntityStmnt(
                    mockServerUrl, nonExistingUri))
        .isInstanceOf(GsiException.class)
        .hasMessageContaining(
            "Content of parameter redirect_uri ["
                + nonExistingUri
                + "] not found in entity statement");
  }

  @Test
  void verifySignature_Token1Valid() throws IOException {
    final PublicKey publicKey =
        CryptoLoader.getCertificateFromPem(
                FileUtils.readFileToByteArray(
                    new File("src/test/resources/cert/fachdienst-sig.pem")))
            .getPublicKey();
    assertDoesNotThrow(
        () ->
            EntityStmntRpService.verifySignature(
                ENTITY_STMNT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2043, publicKey));
  }

  @Test
  void verifySignature_Token2Valid() throws IOException {
    final PublicKey publicKey =
        CryptoLoader.getCertificateFromPem(
                FileUtils.readFileToByteArray(
                    new File("src/test/resources/cert/fedmaster-sig.pem")))
            .getPublicKey();
    assertDoesNotThrow(
        () ->
            EntityStmntRpService.verifySignature(
                ENTITY_STMNT_ABOUT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2043, publicKey));
  }

  @Test
  void verifySignature_TokenExpired() throws IOException {
    final PublicKey publicKey =
        CryptoLoader.getCertificateFromPem(
                FileUtils.readFileToByteArray(
                    new File("src/test/resources/cert/fachdienst-sig.pem")))
            .getPublicKey();
    assertThatThrownBy(
            () ->
                EntityStmntRpService.verifySignature(
                    ENTITY_STMNT_IDP_FACHDIENST_EXPIRED, publicKey))
        .isInstanceOf(IdpJwtExpiredException.class);
  }
}
