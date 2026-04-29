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

package de.gematik.idp.gsi.server.tools;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import kong.unirest.core.json.JSONArray;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

@Slf4j
class VersicherteImporterTest {

  @TempDir Path tempDir;

  @Test
  void testAppendDataFromCsvToVersicherteJson() throws IOException {
    final Path csvPath = createCsvPath();
    final Path jsonPath = createJsonPath();

    VersicherteImporter.appendDataFromCsvToVersicherteJson(csvPath, jsonPath);

    final JSONArray updated = readJsonArray(jsonPath);
    assertThat(updated.length()).isEqualTo(5);

    // drittes Json-Object ist erster importierter csv-Eintrag
    assertThat(updated.getJSONObject(3).getString("birthdate")).isEqualTo("1971-01-16");
  }

  @Test
  void testFixMissingDataInBirthdate() {
    assertThat(VersicherteImporter.fixMissingDataInBirthdate("19801200")).isEqualTo("19801215");
    assertThat(VersicherteImporter.fixMissingDataInBirthdate("19800000")).isEqualTo("19800701");
  }

  private Path createCsvPath() throws IOException {
    final Path csvToVersicherteTest =
        Path.of("src/test/resources/csvToVersicherte.gesundheitsidTest.csv");

    final Path csvPath = tempDir.resolve("csvToJsonTest.csv");
    Files.writeString(csvPath, Files.readString(csvToVersicherteTest, StandardCharsets.UTF_8));
    return csvPath;
  }

  private Path createJsonPath() throws IOException {
    final Path bisherigeVersicherte =
        Path.of("src/test/resources/versicherte.gesundheitsidTest.json");
    final Path neueVersicherte = tempDir.resolve("versicherte.json");
    Files.writeString(
        neueVersicherte, Files.readString(bisherigeVersicherte, StandardCharsets.UTF_8));
    return neueVersicherte;
  }

  private JSONArray readJsonArray(final Path jsonPath) throws IOException {
    final String json = Files.readString(jsonPath, StandardCharsets.UTF_8);
    return new JSONArray(json);
  }
}
