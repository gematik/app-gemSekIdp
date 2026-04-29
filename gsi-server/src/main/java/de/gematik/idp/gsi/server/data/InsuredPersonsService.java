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

import static de.gematik.idp.field.ClaimName.TELEMATIK_ID;
import static de.gematik.idp.gsi.server.data.GsiConstants.CLAIM_VALUE_ORGANIZATION_GEMATIK;
import static de.gematik.idp.gsi.server.data.GsiConstants.CLAIM_VALUE_PROFESSION_VERSICHERTER;
import static de.gematik.idp.gsi.server.data.GsiConstants.VALID_CLAIMS;

import de.gematik.idp.field.ClaimName;
import de.gematik.idp.gsi.server.exceptions.GsiException;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

@Service
@RequiredArgsConstructor
public class InsuredPersonsService {

  private final String insuredPersonsJsonFilePath;
  private Map<String, Map<String, Object>> persons;

  public Map<String, Object> getPerson(final String kvnr) {
    final Optional<Map<String, Object>> thisPerson = Optional.ofNullable(getPersons().get(kvnr));
    return thisPerson.orElseGet(() -> returnEntryWithKvnrAndUnknown(kvnr));
  }

  public Map<String, Map<String, Object>> getPersons() {
    initPersons();
    return persons;
  }

  private void initPersons() {
    if (null == persons) {
      persons = readInsuredPersons(insuredPersonsJsonFilePath);
    }
  }

  private Map<String, Map<String, Object>> readInsuredPersons(final String filePath) {
    try {
      final List<Map<String, Object>> dataList = readJsonFileToList(filePath);
      return convertListToKvnrMap(dataList);
    } catch (final IOException | tools.jackson.core.exc.StreamReadException e) {
      throw new GsiException("Could not read insured persons from file.", e);
    }
  }

  private Map<String, Object> returnEntryWithKvnrAndUnknown(final String kvnr) {
    final Map<String, Object> unknownEntry = new HashMap<>();

    VALID_CLAIMS.forEach(key -> unknownEntry.put(key, "unknown"));
    unknownEntry.put(ClaimName.BIRTHDATE.getJoseName(), "1990-01-01");
    unknownEntry.put(
        ClaimName.TELEMATIK_PROFESSION.getJoseName(), CLAIM_VALUE_PROFESSION_VERSICHERTER);
    unknownEntry.put(
        ClaimName.TELEMATIK_ORGANIZATION.getJoseName(), CLAIM_VALUE_ORGANIZATION_GEMATIK);
    unknownEntry.put(ClaimName.TELEMATIK_ID.getJoseName(), kvnr);
    return unknownEntry;
  }

  private static List<Map<String, Object>> readJsonFileToList(final String filePath)
      throws IOException {
    final ObjectMapper objectMapper = JsonMapper.builder().build();

    // Use ClassLoader to get the input stream for the resource
    final InputStream inputStream =
        InsuredPersonsService.class.getClassLoader().getResourceAsStream(filePath);

    if (inputStream == null) {
      throw new IOException("File not found: " + filePath);
    }

    // Read the JSON file into a List of Map<String, String>
    return objectMapper.readValue(inputStream, new TypeReference<>() {});
  }

  private static Map<String, Map<String, Object>> convertListToKvnrMap(
      final List<Map<String, Object>> dataList) {
    final Map<String, Map<String, Object>> resultMap = new HashMap<>();

    for (final Map<String, Object> dataMap : dataList) {
      final String id = (String) dataMap.get(TELEMATIK_ID.getJoseName());
      if (id != null) {
        resultMap.put(id, dataMap);
      }
    }

    return resultMap;
  }
}
