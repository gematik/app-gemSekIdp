/*
 *  Copyright 2023 gematik GmbH
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

package de.gematik.idp.gsi.server.data;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import com.fasterxml.jackson.core.JsonParseException;
import de.gematik.idp.field.ClaimName;
import de.gematik.idp.gsi.server.exceptions.GsiException;
import java.io.IOException;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.annotation.DirtiesContext.ClassMode;

@Slf4j
@SpringBootTest
@DirtiesContext(classMode = ClassMode.AFTER_CLASS)
class InsuredPersonsServiceTest {

  @Autowired InsuredPersonsService insuredPersonsService;

  @Test
  void getPersonFromService() {
    assertThat(insuredPersonsService.getPersons().get("X110411675")).isNotNull();
  }

  @Test
  void getPersons() {
    assertDoesNotThrow(() -> new InsuredPersonsService("versicherte.gesundheitsid.json"));
  }

  @Test
  void getPersonX110411675() {
    final InsuredPersonsService iPr = new InsuredPersonsService("versicherte.gesundheitsid.json");
    assertThat(iPr.getPersons().get("X110411675")).isNotNull();
  }

  @Test
  void getFamilyNameOfPersonX110411675() {
    final InsuredPersonsService iPr = new InsuredPersonsService("versicherte.gesundheitsid.json");
    assertThat(iPr.getPersons().get("X110411675"))
        .containsEntry(ClaimName.TELEMATIK_FAMILY_NAME.getJoseName(), "Bödefeld");
  }

  @Test
  void checkInsuredPersonsList() {
    final InsuredPersonsService iPr = new InsuredPersonsService("versicherte.gesundheitsid.json");
    iPr.getPersons()
        .values()
        .forEach(
            person -> {
              try {
                assertThat(person.size()).isBetween(10, 12);
              } catch (final AssertionError e) {
                log.error("Assertion failed for person: " + person);
                throw e; // rethrow the AssertionError to fail the test
              }
            });
  }

  @Test
  void getPersonFileNotFound() {
    final String invalidFilePath = "invalidFilePath";
    final InsuredPersonsService iPr = new InsuredPersonsService(invalidFilePath);
    assertThatThrownBy(iPr::getPersons)
        .isInstanceOf(GsiException.class)
        .hasRootCauseExactlyInstanceOf(IOException.class);
  }

  @Test
  void getPersonFileNotJson() {
    final String invalidFilePath = "application.yml";
    final InsuredPersonsService iPr = new InsuredPersonsService(invalidFilePath);
    assertThatThrownBy(iPr::getPersons)
        .isInstanceOf(GsiException.class)
        .hasRootCauseExactlyInstanceOf(JsonParseException.class);
  }
}
