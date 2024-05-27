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

package de.gematik.idp.gsi.fedmaster.configuration;

import de.gematik.idp.data.KeyConfig;
import de.gematik.idp.gsi.fedmaster.data.IdentityProviderConfig;
import de.gematik.idp.gsi.fedmaster.data.RelyingPartyConfig;
import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties("fedmaster")
@Getter
@Setter
@ToString
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class FedMasterConfiguration {

  private String serverUrl;
  private KeyConfig fedmasterSigPrivKeyConfig;
  private KeyConfig fedmasterSigPubKeyConfig;
  private List<RelyingPartyConfig> relyingPartyConfigs;
  private List<IdentityProviderConfig> identityProviderConfigs;
  private String loglevel;

  @Bean
  public List<RelyingPartyConfig> relyingPartyConfigs() {
    return relyingPartyConfigs;
  }

  @Bean
  public List<IdentityProviderConfig> identityProviderConfigs() {
    return identityProviderConfigs;
  }
}
