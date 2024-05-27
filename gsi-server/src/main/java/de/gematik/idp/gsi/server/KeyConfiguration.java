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
import de.gematik.idp.crypto.KeyUtility;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.data.FederationPrivKey;
import de.gematik.idp.data.FederationPubKey;
import de.gematik.idp.data.KeyConfig;
import de.gematik.idp.data.KeyConfigurationBase;
import de.gematik.idp.file.ResourceReader;
import de.gematik.idp.gsi.server.configuration.GsiConfiguration;
import de.gematik.idp.gsi.server.exceptions.GsiException;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@RequiredArgsConstructor
public class KeyConfiguration implements KeyConfigurationBase {

  private final GsiConfiguration gsiConfiguration;

  @Bean
  public FederationPrivKey esSigPrivKey() {
    return getFederationPrivKey(gsiConfiguration.getEsSigPrivKeyConfig());
  }

  @Bean
  public FederationPubKey esSigPubKey() {
    return getFederationPubkey(gsiConfiguration.getEsSigPubKeyConfig());
  }

  @Bean
  public FederationPrivKey tokenSigPrivKey() {
    return getFederationPrivKey(gsiConfiguration.getTokenSigPrivKeyConfig());
  }

  @Bean
  public FederationPubKey tokenSigPubKey() {
    return getFederationPubkey(gsiConfiguration.getTokenSigPubKeyConfig());
  }

  @Bean
  public IdpJwtProcessor jwtProcessorEsSigPrivKey() {
    return new IdpJwtProcessor(
        esSigPrivKey().getIdentity().getPrivateKey(), esSigPrivKey().getKeyId());
  }

  @Bean
  public IdpJwtProcessor jwtProcessorTokenSigPrivKey() {
    return new IdpJwtProcessor(
        tokenSigPrivKey().getIdentity().getPrivateKey(), tokenSigPrivKey().getKeyId());
  }

  @Bean
  public PublicKey fedmasterSigKey() throws IOException {
    return KeyUtility.readX509PublicKey(
        ResourceReader.getFileFromResourceAsTmpFile(
            gsiConfiguration.getFedmasterSigPubKeyFilePath()));
  }

  private FederationPrivKey getFederationPrivKey(final KeyConfig keyConfiguration) {
    try {
      final PrivateKey privateKey =
          KeyUtility.readX509PrivateKeyPlain(
              ResourceReader.getFileFromResourceAsTmpFile(keyConfiguration.getFileName()));
      final PkiIdentity pkiIdentity = new PkiIdentity();
      pkiIdentity.setPrivateKey(privateKey);
      final FederationPrivKey federationPrivKey = new FederationPrivKey(pkiIdentity);
      federationPrivKey.setKeyId(keyConfiguration.getKeyId());
      federationPrivKey.setUse(Optional.of(keyConfiguration.getUse()));
      federationPrivKey.setAddX5c(Optional.of(keyConfiguration.isX5cInJwks()));
      return federationPrivKey;
    } catch (final IOException e) {
      throw new GsiException(
          "Error while loading Gsi-Server Key from resource '"
              + keyConfiguration.getFileName()
              + "'",
          e);
    }
  }

  private FederationPubKey getFederationPubkey(final KeyConfig keyConfiguration) {
    try {
      final PublicKey publicKey =
          KeyUtility.readX509PublicKey(
              ResourceReader.getFileFromResourceAsTmpFile(keyConfiguration.getFileName()));
      final FederationPubKey federationPubKey = new FederationPubKey();
      federationPubKey.setPublicKey(Optional.ofNullable(publicKey));
      federationPubKey.setKeyId(keyConfiguration.getKeyId());
      federationPubKey.setUse(Optional.of(keyConfiguration.getUse()));
      return federationPubKey;
    } catch (final IOException e) {
      throw new GsiException(
          "Error while loading Gsi-Server Key from resource '"
              + keyConfiguration.getFileName()
              + "'",
          e);
    }
  }
}
