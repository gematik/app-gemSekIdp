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

import de.gematik.idp.gsi.server.data.GsiConstants;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class TrustedCertificateLoader {

  public static List<X509Certificate> loadTrustedCertificates(final String directory)
      throws CertificateException {
    final List<X509Certificate> certs = new ArrayList<>();
    File dir = new File(directory);
    if (!dir.exists() || !dir.isDirectory()) {
      final ClassLoader cl = Thread.currentThread().getContextClassLoader();
      final java.net.URL url = cl.getResource(directory);
      if (url == null) {
        return certs;
      }
      dir = new File(url.getFile());
      if (!dir.exists() || !dir.isDirectory()) {
        return certs;
      }
    }
    final CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
    final File[] files = dir.listFiles((d, name) -> name.endsWith(".pem"));
    if (files != null) {
      for (final File file : files) {
        try (final FileInputStream fis = new FileInputStream(file)) {
          final X509Certificate cert = (X509Certificate) certFactory.generateCertificate(fis);
          if (cert != null) {
            certs.add(cert);
          } else {
            log.warn("CertificateFactory returned null for file: {}", file.getName());
          }
        } catch (final CertificateException | IOException e) {
          log.warn("Could not load certificate from file: {}: {}", file.getName(), e.getMessage());
        }
      }
    }
    return certs;
  }

  public static List<X509Certificate> loadTrustedCertificates() throws CertificateException {
    return loadTrustedCertificates(GsiConstants.TRUSTED_CERTS_DIR);
  }
}
