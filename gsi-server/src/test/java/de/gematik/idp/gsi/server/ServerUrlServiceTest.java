/*
 *  Copyright [2023] gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.idp.gsi.server;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

import de.gematik.idp.IdpConstants;
import de.gematik.idp.gsi.server.configuration.GsiConfiguration;
import de.gematik.idp.gsi.server.services.ServerUrlService;
import org.junit.jupiter.api.Test;
import org.mockserver.client.MockServerClient;
import org.mockserver.model.MediaType;
import org.mockserver.springtest.MockServerTest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.annotation.DirtiesContext.ClassMode;

@SpringBootTest
@DirtiesContext(classMode = ClassMode.BEFORE_EACH_TEST_METHOD)
@MockServerTest("server.url=http://localhost:${mockServerPort}")
class ServerUrlServiceTest {

  @Value("${server.url}")
  private String mockServerUrl;

  @Autowired ServerUrlService serverUrlService;
  @Autowired GsiConfiguration gsiConfiguration;
  private MockServerClient mockServerClient;

  private final String ENTITY_STATEMENT_FED_MASTER =
      "eyJ0eXAiOiJlbnRpdHktc3RhdGVtZW50K2p3dCIsImtpZCI6InB1a19mZWRtYXN0ZXJfc2lnIiwiYWxnIjoiRVMyNTYifQ.eyJpc3MiOiJodHRwczovL2FwcC1yZWYuZmVkZXJhdGlvbm1hc3Rlci5kZSIsInN1YiI6Imh0dHBzOi8vYXBwLXJlZi5mZWRlcmF0aW9ubWFzdGVyLmRlIiwiaWF0IjoxNjgzNzAyMDA1LCJleHAiOjE2ODM3ODg0MDUsImp3a3MiOnsia2V5cyI6W3sia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJjZElSOGRMYnFhR3J6Zmd5dTM2NUtNNXMwMHpqRnE4REZhVUZxQnZyV0xzIiwieSI6IlhWcDF5U0oya2pFSW5walRaeTB3RDU5YWZFWEVMcGNrMGZrN3ZyTVdyYnciLCJraWQiOiJwdWtfZmVkbWFzdGVyX3NpZyIsInVzZSI6InNpZyIsImFsZyI6IkVTMjU2In1dfSwibWV0YWRhdGEiOnsiZmVkZXJhdGlvbl9lbnRpdHkiOnsiZmVkZXJhdGlvbl9mZXRjaF9lbmRwb2ludCI6Imh0dHBzOi8vYXBwLXJlZi5mZWRlcmF0aW9ubWFzdGVyLmRlL2ZlZGVyYXRpb24vZmV0Y2giLCJmZWRlcmF0aW9uX2xpc3RfZW5kcG9pbnQiOiJodHRwczovL2FwcC1yZWYuZmVkZXJhdGlvbm1hc3Rlci5kZS9mZWRlcmF0aW9uL2xpc3QiLCJpZHBfbGlzdF9lbmRwb2ludCI6Imh0dHBzOi8vYXBwLXJlZi5mZWRlcmF0aW9ubWFzdGVyLmRlL2ZlZGVyYXRpb24vbGlzdGlkcHMifX19.ItgoyO5UBnSH645qMhOM_06hYoPBiGKvcsAE9h5XufY1ae3bS3W-6nbNQXyjOzYDPQPSIwwApRemLZaJvzeHAA";

  @Test
  void testDetermineServerUrl() {
    assertThat(serverUrlService.determineServerUrl()).contains(":8085");
  }

  @Test
  void testFedmasterServerUrl() {
    assertThat(serverUrlService.determineFedmasterUrl())
        .isEqualTo("https://app-ref.federationmaster.de");
  }

  @Test
  void testDetermineFetchEntityStatementEndpoint() {
    mockServerClient
        .when(request().withMethod("GET").withPath(IdpConstants.ENTITY_STATEMENT_ENDPOINT))
        .respond(
            response()
                .withStatusCode(200)
                .withContentType(MediaType.APPLICATION_JSON)
                .withBody(ENTITY_STATEMENT_FED_MASTER));
    gsiConfiguration.setFedmasterUrl(mockServerUrl);
    assertThat(serverUrlService.determineFetchEntityStatementEndpoint())
        .isEqualTo("https://app-ref.federationmaster.de/federation/fetch");
  }
}
