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

package de.gematik.idp.gsi.server.util;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.File;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.List;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class TrustedCertificateLoaderTest {

  @Test
  @SneakyThrows
  void test_loadTrustedCertificates_returnsCertsIfPresent() {
    final List<X509Certificate> certs = TrustedCertificateLoader.loadTrustedCertificates();
    assertThat(certs).isNotNull();
    assertThat(certs.size()).isGreaterThanOrEqualTo(1);
    for (final X509Certificate cert : certs) {
      assertThat(cert).isInstanceOf(X509Certificate.class);
    }
  }

  @Test
  @SneakyThrows
  void test_loadTrustedCertificates_returnsEmptyListIfUrlIsNull() {
    final List<X509Certificate> certs =
        TrustedCertificateLoader.loadTrustedCertificates("not_existing_dir");
    assertThat(certs).isNotNull();
    assertThat(certs).isEmpty();
  }

  @Test
  @SneakyThrows
  void test_loadTrustedCertificates_returnsEmptyListIfNotDirectory() {
    final File tempFile = File.createTempFile("not_a_dir", ".tmp");
    tempFile.deleteOnExit();
    final List<X509Certificate> certs =
        TrustedCertificateLoader.loadTrustedCertificates(tempFile.getAbsolutePath());
    assertThat(certs).isNotNull();
    assertThat(certs).isEmpty();
  }

  @Test
  @SneakyThrows
  void test_loadTrustedCertificates_handlesCertificateExceptionOrIOException(
      @TempDir final Path tempDir) {
    final File invalidFile = tempDir.resolve("invalid.pem").toFile();
    invalidFile.createNewFile();
    invalidFile.deleteOnExit();
    final List<X509Certificate> certs =
        TrustedCertificateLoader.loadTrustedCertificates(tempDir.toAbsolutePath().toString());
    assertThat(certs).isNotNull();
    assertThat(certs).isEmpty();
  }
}
