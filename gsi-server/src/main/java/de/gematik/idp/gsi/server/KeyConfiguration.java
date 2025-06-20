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

package de.gematik.idp.gsi.server;

import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.crypto.CryptoLoader;
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
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Optional;
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
  public FederationPrivKey esSigPrivKey() {
    return getFederationPrivKeyFromPem(gsiConfiguration.getEsSigPrivKeyConfig());
  }

  @Bean
  public FederationPubKey esSigPubKey() {
    return getFederationPubkeyFromPem(gsiConfiguration.getEsSigPubKeyConfig());
  }

  @Bean
  public FederationPrivKey tokenSigPrivKey() {
    return getFederationPrivKeyFromP12(gsiConfiguration.getTokenSigKeyConfig());
  }

  @Bean
  public FederationPubKey tokenSigPubKey() {
    return getFederationPubkeyFromP12(gsiConfiguration.getTokenSigKeyConfig());
  }

  @Bean
  public IdpJwtProcessor jwtProcessorEsSigPrivKey() {
    return new IdpJwtProcessor(
        esSigPrivKey().getIdentity().getPrivateKey(), esSigPrivKey().getKeyId());
  }

  @Bean
  public IdpJwtProcessor jwtProcessorTokenSigKey() {
    return new IdpJwtProcessor(
        tokenSigPrivKey().getIdentity(), Optional.of(tokenSigPrivKey().getKeyId()));
  }

  @Bean
  public PublicKey fedmasterSigKey() throws IOException {
    return KeyUtility.readX509PublicKey(
        ResourceReader.getFileFromResourceAsTmpFile(
            gsiConfiguration.getFedmasterSigPubKeyFilePath()));
  }

  private FederationPrivKey getFederationPrivKeyFromP12(final KeyConfig keyConfiguration) {
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

  private FederationPubKey getFederationPubkeyFromP12(final KeyConfig keyConfiguration) {
    final Resource resource = resourceLoader.getResource(keyConfiguration.getFileName());
    try (final InputStream inputStream = resource.getInputStream()) {
      final PkiIdentity pkiIdentity =
          CryptoLoader.getIdentityFromP12(StreamUtils.copyToByteArray(inputStream), "00");
      final X509Certificate cert = pkiIdentity.getCertificate();
      return new FederationPubKey(
          Optional.of(cert),
          Optional.empty(),
          keyConfiguration.getKeyId(),
          Optional.of(keyConfiguration.getUse()));
    } catch (final IOException e) {
      throw new GsiException(
          "Error while loading Gsi-Server Key from resource '"
              + keyConfiguration.getFileName()
              + "'",
          e);
    }
  }

  private FederationPrivKey getFederationPrivKeyFromPem(final KeyConfig keyConfiguration) {
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

  private FederationPubKey getFederationPubkeyFromPem(final KeyConfig keyConfiguration) {
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
