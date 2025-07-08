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

package de.gematik.idp.gsi.fedmaster;

import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.crypto.KeyUtility;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.data.FederationPrivKey;
import de.gematik.idp.data.FederationPubKey;
import de.gematik.idp.data.KeyConfig;
import de.gematik.idp.file.ResourceReader;
import de.gematik.idp.gsi.fedmaster.configuration.FedMasterConfiguration;
import de.gematik.idp.gsi.fedmaster.exceptions.FedmasterException;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@RequiredArgsConstructor
public class KeyConfiguration {

  private final FedMasterConfiguration fedMasterConfiguration;

  @Bean
  public FederationPrivKey esSigPrivKey() {
    return getFederationPrivKey(fedMasterConfiguration.getFedmasterSigPrivKeyConfig());
  }

  @Bean
  public FederationPubKey esSigPubKey() {
    return getFederationPubKey(fedMasterConfiguration.getFedmasterSigPubKeyConfig());
  }

  @Bean
  public IdpJwtProcessor jwtProcessorFedmasterSigPrivKey() {
    return new IdpJwtProcessor(
        esSigPrivKey().getIdentity().getPrivateKey(), esSigPrivKey().getKeyId());
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
      throw new FedmasterException(
          "Error while loading Key from resource '" + keyConfiguration.getFileName() + "'", e);
    }
  }

  public static FederationPubKey getFederationPubKey(final KeyConfig keyConfiguration) {
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
      throw new FedmasterException(
          "Error while loading Key from resource '" + keyConfiguration.getFileName() + "'", e);
    }
  }
}
