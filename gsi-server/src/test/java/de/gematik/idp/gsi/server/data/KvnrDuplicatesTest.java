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

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

class KvnrDuplicatesTest {

  private static final String RESOURCE_NAME = "/versicherte.gesundheitsid.json";

  @Test
  void testKvnrNoDuplicates() throws Exception {
    final ObjectMapper mapper = JsonMapper.builder().build();
    try (final InputStream inputStream = getClass().getResourceAsStream(RESOURCE_NAME)) {
      if (inputStream == null) {
        throw new Exception("Resource not found: " + RESOURCE_NAME);
      }

      final List<Map<String, Object>> data =
          mapper.readValue(inputStream, new TypeReference<>() {});

      final Set<Object> duplicates =
          data.stream()
              .map(m -> m.get("urn:telematik:claims:id"))
              .filter(Objects::nonNull)
              .collect(Collectors.groupingBy(Function.identity(), Collectors.counting()))
              .entrySet()
              .stream()
              .filter(e -> e.getValue() > 1)
              .map(Map.Entry::getKey)
              .collect(Collectors.toSet());

      assertTrue(duplicates.isEmpty(), "Duplicates found. " + duplicates);
    }
  }
}
