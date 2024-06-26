/*
 *  Copyright 2024 gematik GmbH
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

package de.gematik.idp.gsi.fedmaster;

import de.gematik.idp.gsi.fedmaster.services.EntityStatementBuilder;
import de.gematik.idp.gsi.fedmaster.services.EntityStatementFederationMemberBuilder;
import de.gematik.idp.gsi.fedmaster.services.FedListBuilder;
import de.gematik.idp.gsi.fedmaster.services.IdpListBuilder;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@RequiredArgsConstructor
public class FlowBeanCreation {

  @Bean
  public EntityStatementBuilder entityStatementBuilder() {
    return new EntityStatementBuilder();
  }

  @Bean
  public EntityStatementFederationMemberBuilder entityStatementFederationMemberBuilder() {
    return new EntityStatementFederationMemberBuilder();
  }

  @Bean
  public IdpListBuilder entityListBuilder() {
    return new IdpListBuilder();
  }

  @Bean
  public FedListBuilder fedListBuilder() {
    return new FedListBuilder();
  }
}
