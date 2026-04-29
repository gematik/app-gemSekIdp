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

package de.gematik.idp.gsi.server.data;

import static de.gematik.idp.gsi.server.data.GsiConstants.FALLBACK_KVNR;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.gematik.idp.field.ClaimName;
import de.gematik.idp.gsi.server.exceptions.GsiException;
import java.io.IOException;
import java.util.Map;
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
  final String PATH_TO_VERSICHERTEJSON = "versicherte.gesundheitsid.json";

  @Test
  void test_getPersonFromService_VALID() {
    assertThat(insuredPersonsService.getPersons().get(FALLBACK_KVNR)).isNotNull();
  }

  @Test
  void test_getPersons_VALID() {
    assertDoesNotThrow(() -> new InsuredPersonsService(PATH_TO_VERSICHERTEJSON));
  }

  @Test
  void test_getPersonFallback_VALID() {
    final InsuredPersonsService iPr = new InsuredPersonsService(PATH_TO_VERSICHERTEJSON);
    assertThat(iPr.getPersons().get(FALLBACK_KVNR)).isNotNull();
  }

  @Test
  void test_getFamilyNameOfPersonFallback_VALID() {
    final InsuredPersonsService iPr = new InsuredPersonsService(PATH_TO_VERSICHERTEJSON);
    assertThat(iPr.getPersons().get(FALLBACK_KVNR))
        .containsEntry(ClaimName.TELEMATIK_FAMILY_NAME.getJoseName(), "Bödefeld");
  }

  @Test
  void test_checkInsuredPersonsList_VALID() {
    final InsuredPersonsService iPr = new InsuredPersonsService(PATH_TO_VERSICHERTEJSON);
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
  void test_getPersonFileNotFound_INVALID() {
    final String invalidFilePath = "invalidFilePath";
    final InsuredPersonsService iPr = new InsuredPersonsService(invalidFilePath);
    assertThatThrownBy(iPr::getPersons)
        .isInstanceOf(GsiException.class)
        .hasRootCauseExactlyInstanceOf(IOException.class);
  }

  @Test
  void test_getPersonFileNotJson_INVALID() {
    final String invalidFilePath = "application.yml";
    final InsuredPersonsService iPs = new InsuredPersonsService(invalidFilePath);
    assertThatThrownBy(iPs::getPersons)
        .isInstanceOf(GsiException.class)
        .hasRootCauseExactlyInstanceOf(tools.jackson.core.exc.StreamReadException.class);
  }

  @Test
  void test_getPersonByUnknownKvnr() {
    final InsuredPersonsService iPr = new InsuredPersonsService(PATH_TO_VERSICHERTEJSON);
    final Map<String, Object> unknownPerson = iPr.getPerson("A123456789");
    assertThat(unknownPerson.isEmpty()).isFalse();

    assertThat(unknownPerson.get(ClaimName.TELEMATIK_FAMILY_NAME.getJoseName()))
        .isEqualTo("unknown");
    assertThat(unknownPerson.get(ClaimName.TELEMATIK_PROFESSION.getJoseName()))
        .isEqualTo(GsiConstants.CLAIM_VALUE_PROFESSION_VERSICHERTER);
    assertThat(unknownPerson.get(ClaimName.TELEMATIK_ORGANIZATION.getJoseName()))
        .isEqualTo(GsiConstants.CLAIM_VALUE_ORGANIZATION_GEMATIK);
    assertThat(unknownPerson.get(ClaimName.TELEMATIK_ID.getJoseName())).isEqualTo("A123456789");
  }

  @Test
  void test_unknownKvnrMustNotOverwriteDefaultEntry() {
    final InsuredPersonsService iPr = new InsuredPersonsService(PATH_TO_VERSICHERTEJSON);
    final String kvnrUnknownPerson = "A111111111";
    // get the fallback person and check kvnr
    final Map<String, Object> fallbackPerson = iPr.getPersons().get(FALLBACK_KVNR);
    assertThat(fallbackPerson.get(ClaimName.TELEMATIK_ID.getJoseName())).isEqualTo(FALLBACK_KVNR);

    // get unknown person and check kvnr
    final Map<String, Object> unknownPerson = iPr.getPerson(kvnrUnknownPerson);
    assertThat(unknownPerson.get(ClaimName.TELEMATIK_ID.getJoseName()))
        .isEqualTo(kvnrUnknownPerson);

    // get the fallback person again and check kvnr was not overwritten by unknown person
    assertThat(fallbackPerson.get(ClaimName.TELEMATIK_ID.getJoseName())).isEqualTo(FALLBACK_KVNR);
  }
}
