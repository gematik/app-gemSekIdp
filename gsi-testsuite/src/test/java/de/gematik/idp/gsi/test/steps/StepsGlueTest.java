/*
 * Copyright (Change Date see Readme), gematik GmbH
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
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 */

package de.gematik.idp.gsi.test.steps;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.gematik.test.tiger.common.config.TigerGlobalConfiguration;
import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.InvalidJwtSignatureException;
import org.junit.jupiter.api.Test;

@Slf4j
class StepsGlueTest {

  private static final String EXPIRED_JWS =
      "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InB1a19mZWRfc2lnIn0.eyJpc3MiOiJodHRwOi8vZ3N0b3BkaDIudG9wLmxvY2FsOjg1NzQiLCJzdWIiOiJodHRwOi8vZ3N0b3BkaDIudG9wLmxvY2FsOjg1NzQiLCJpYXQiOjE2NjYzMzU0ODAsImV4cCI6MTY2Njk0MDI4MCwiandrcyI6eyJrZXlzIjpbeyJ1c2UiOiJzaWciLCJraWQiOiJwdWtfZmVkX3NpZyIsImt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoieEppeGtRdjlENVpSMUp1cW9iREtjRmZBY3YwYklKbjhJUTRjTFJ3WnVSbyIsInkiOiJpbUJPdWJydzdXel9tMlF4WnBNS2JNdjdPU3ZDd2FSenN1YlV4U3RfWkEwIn1dfSwibWV0YWRhdGEiOnsiZmVkZXJhdGlvbl9lbnRpdHkiOnsiZmVkZXJhdGlvbl9mZXRjaF9lbmRwb2ludCI6Imh0dHA6Ly9nc3RvcGRoMi50b3AubG9jYWw6ODU3NC9mZWRlcmF0aW9uX2ZldGNoX2VuZHBvaW50IiwiZmVkZXJhdGlvbl9saXN0X2VuZHBvaW50IjoiaHR0cDovL2dzdG9wZGgyLnRvcC5sb2NhbDo4NTc0L2ZlZGVyYXRpb25fbGlzdCIsImlkcF9saXN0X2VuZHBvaW50IjoiaHR0cDovL2dzdG9wZGgyLnRvcC5sb2NhbDo4NTc0Ly53ZWxsLWtub3duL2lkcF9saXN0In19fQ.4LIyPcOW58kreey7oJZoG5E9riiJvIRoUsAZvBHnSuTxGiiGjGDGO9NPcOxYhr5Msu1rAxFmAONbyUMnHuo2aA";
  private static final JsonNode FED_SIG_KEY_AS_JWK;

  static {
    try {
      FED_SIG_KEY_AS_JWK =
          new ObjectMapper()
              .readTree(
                  "{\"use\":\"sig\",\"kid\":\"puk_fed_sig\",\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"xJixkQv9D5ZR1JuqobDKcFfAcv0bIJn8IQ4cLRwZuRo\",\"y\":\"imBOubrw7Wz_m2QxZpMKbMv7OSvCwaRzsubUxSt_ZA0\"}");
    } catch (final JsonProcessingException e) {
      throw new RuntimeException(e);
    }
  }

  private static final List<JsonNode> TRUSTSTORE = new ArrayList<>();
  private static final String KID_OF_FED_SIG_KEY = "puk_fed_sig";

  static {
    TRUSTSTORE.add(FED_SIG_KEY_AS_JWK);
  }

  @Test
  @SneakyThrows
  void getJsonWebKeyTest() {
    assertThat(StepsGlue.getJsonWebKey(TRUSTSTORE, KID_OF_FED_SIG_KEY)).isNotNull();
    assertThatThrownBy(() -> StepsGlue.getJsonWebKey(TRUSTSTORE, "invalid_kid"))
        .isInstanceOf(NoSuchElementException.class);
  }

  @Test
  @SneakyThrows
  void checkSignatureTest_isExpired() {
    final JsonWebKey jsonWebKey = StepsGlue.getJsonWebKey(TRUSTSTORE, KID_OF_FED_SIG_KEY);
    assertThatThrownBy(() -> StepsGlue.validateJwsSignature(EXPIRED_JWS, jsonWebKey))
        .isInstanceOf(InvalidJwtException.class)
        .hasMessageContaining("no longer valid");
  }

  @Test
  @SneakyThrows
  void checkSignatureTest_isInvalid() {
    final String invalidJws =
        "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InB1a19mZWRfc2lnIn0.eyJpc3MiOiJodHRwOi8vZ3N0b3BkaDIudG9wLmxvY2FsOjg1NzQiLCJzdWIiOiJodHRwOi8vZ3N0b3BkaDIudG9wLmxvY2FsOjg1NzQiLCJpYXQiOjE2NjYzMzU0ODAsImV4cCI6MTY2Njk0MDI4MCwiandrcyI6eyJrZXlzIjpbeyJ1c2UiOiJzaWciLCJraWQiOiJwdWtfZmVkX3NpZyIsImt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoieEppeGtRdjlENVpSMUp1cW9iREtjRmZBY3YwYklKbjhJUTRjTFJ3WnVSbyIsInkiOiJpbUJPdWJydzdXel9tMlF4WnBNS2JNdjdPU3ZDd2FSenN1YlV4U3RfWkEwIn1dfSwibWV0YWRhdGEiOnsiZmVkZXJhdGlvbl9lbnRpdHkiOnsiZmVkZXJhdGlvbl9mZXRjaF9lbmRwb2ludCI6Imh0dHA6Ly9nc3RvcGRoMi50b3AubG9jYWw6ODU3NC9mZWRlcmF0aW9uX2ZldGNoX2VuZHBvaW50IiwiZmVkZXJhdGlvbl9saXN0X2VuZHBvaW50IjoiaHR0cDovL2dzdG9wZGgyLnRvcC5sb2NhbDo4NTc0L2ZlZGVyYXRpb25fbGlzdCIsImlkcF9saXN0X2VuZHBvaW50IjoiaHR0cDovL2dzdG9wZGgyLnRvcC5sb2NhbDo4NTc0Ly53ZWxsLWtub3duL2lkcF9saXN0In19fQ.4LIyPcOW58kreey7oJZoG5E9riiJvIRoUsAZvBHnSubxGiiGjGDGO9NPcOxYhr5Msu1rAxFmAONbyUMnHuo2aA==";
    final JsonWebKey jsonWebKey = StepsGlue.getJsonWebKey(TRUSTSTORE, KID_OF_FED_SIG_KEY);
    assertThatThrownBy(() -> StepsGlue.validateJwsSignature(invalidJws, jsonWebKey))
        .isInstanceOf(InvalidJwtSignatureException.class);
  }

  @Test
  void checkReadPropertiesFromYaml_entryForSpecificKey() {
    final String pathInYaml = "gsi.redirectUri";
    assertThat(TigerGlobalConfiguration.readString(pathInYaml, pathInYaml)).contains("http");
  }

  @Test
  void checkReadPropertiesFromYaml_keyNotFound() {
    final String valueButNotPathInYaml = "myValue";
    assertThat(TigerGlobalConfiguration.readString(valueButNotPathInYaml, valueButNotPathInYaml))
        .isEqualTo("myValue");
  }
}
