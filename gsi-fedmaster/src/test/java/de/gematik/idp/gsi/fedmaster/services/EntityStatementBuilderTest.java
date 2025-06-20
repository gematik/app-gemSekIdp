/*
 * Copyright (Date see Readme), gematik GmbH
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

package de.gematik.idp.gsi.fedmaster.services;

import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.idp.gsi.fedmaster.data.EntityStatement;
import jakarta.annotation.Resource;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class EntityStatementBuilderTest {

  @Resource private EntityStatementBuilder entityStatementBuilder;

  @Test
  void buildEntityStatement() {
    final String serverUrl = "http://localhost:59440";
    final String federationFetchEndpoint = serverUrl + "/federation_fetch_endpoint";
    final String fedListEndpoint = serverUrl + "/federation_list";
    final String idpListEndpoint = serverUrl + "/.well-known/idp_list";
    final EntityStatement entityStatement = entityStatementBuilder.buildEntityStatement(serverUrl);
    assertThat(entityStatement).isNotNull();
    assertThat(entityStatement.getMetadata().getFederationEntity().getFederationFetchEndpoint())
        .isEqualTo(federationFetchEndpoint);
    assertThat(entityStatement.getMetadata().getFederationEntity().getFederationListEndpoint())
        .isEqualTo(fedListEndpoint);
    assertThat(entityStatement.getMetadata().getFederationEntity().getIdpListEndpoint())
        .isEqualTo(idpListEndpoint);
  }
}
