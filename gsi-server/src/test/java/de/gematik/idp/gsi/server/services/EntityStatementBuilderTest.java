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

package de.gematik.idp.gsi.server.services;

import static de.gematik.idp.IdpConstants.ENTITY_STATEMENT_TYP;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.data.JwtHelper;
import de.gematik.idp.gsi.server.configuration.GsiConfiguration;
import java.time.ZonedDateTime;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@Slf4j
@SpringBootTest
class EntityStatementBuilderTest {

  @Autowired private IdpJwtProcessor jwtProcessorEsSigPrivKey;
  @Autowired private ObjectMapper objectMapper;
  @Autowired private EntityStatementBuilder entityStatementBuilder;
  @Autowired private ServerUrlService serverUrlService;
  @Autowired private GsiConfiguration gsiConfiguration;

  @Test
  void test_generateEntityStatementValid20Years() {
    final int entityStatementTtlYears = 20;
    final long nowPlus20Years =
        ZonedDateTime.now().plusYears(entityStatementTtlYears).toEpochSecond();
    final String es =
        JwtHelper.signJson(
            jwtProcessorEsSigPrivKey,
            objectMapper,
            entityStatementBuilder.buildEntityStatement(
                "http://localhost:8085",
                "http://localhost:8085",
                gsiConfiguration.getFedmasterUrl(),
                nowPlus20Years),
            ENTITY_STATEMENT_TYP);
    assertThat(es).isNotEmpty();
    log.info("Entity statement (valid {} years):\n{}", entityStatementTtlYears, es);
  }
}
