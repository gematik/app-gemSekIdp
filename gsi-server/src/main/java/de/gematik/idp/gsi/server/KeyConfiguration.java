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

package de.gematik.idp.gsi.server;

import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.crypto.CryptoLoader;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.data.FederationPrivKey;
import de.gematik.idp.data.KeyConfig;
import de.gematik.idp.data.KeyConfigurationBase;
import de.gematik.idp.gsi.server.configuration.GsiConfiguration;
import de.gematik.idp.gsi.server.exceptions.GsiException;
import java.io.IOException;
import java.io.InputStream;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.util.StreamUtils;

@Configuration
@RequiredArgsConstructor
public class KeyConfiguration implements KeyConfigurationBase {

  private final ResourceLoader resourceLoader;
  private final GsiConfiguration gsiConfiguration;

  @Bean
  public FederationPrivKey entityStatementSigKey() {
    return getFederationPrivKey(gsiConfiguration.getSigKeyConfig());
  }

  @Bean
  public FederationPrivKey tokenKey() {
    return getFederationPrivKey(gsiConfiguration.getTokenKeyConfig());
  }

  @Bean
  public IdpJwtProcessor jwtProcessorSigKey() {
    return new IdpJwtProcessor(
        entityStatementSigKey().getIdentity(), entityStatementSigKey().getKeyId());
  }

  @Bean
  public IdpJwtProcessor jwtProcessorTokenKey() {
    return new IdpJwtProcessor(tokenKey().getIdentity(), tokenKey().getKeyId());
  }

  private FederationPrivKey getFederationPrivKey(final KeyConfig keyConfiguration) {
    final Resource resource = resourceLoader.getResource(keyConfiguration.getFileName());
    try (final InputStream inputStream = resource.getInputStream()) {
      final PkiIdentity pkiIdentity =
          CryptoLoader.getIdentityFromP12(StreamUtils.copyToByteArray(inputStream), "00");
      return getFederationPrivKey(keyConfiguration, pkiIdentity);
    } catch (final IOException e) {
      throw new GsiException(
          "Error while loading Gsi-Server Key from resource '"
              + keyConfiguration.getFileName()
              + "'",
          e);
    }
  }
}
