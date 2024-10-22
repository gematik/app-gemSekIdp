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

package de.gematik.idp.gsi.server.util;

import static de.gematik.idp.gsi.server.common.Constants.ENTITY_STMNT_ABOUT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2043;
import static de.gematik.idp.gsi.server.common.Constants.ENTITY_STMNT_IDP_FACHDIENST_EXPIRED;
import static de.gematik.idp.gsi.server.common.Constants.ENTITY_STMNT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2043;
import static de.gematik.idp.gsi.server.common.Constants.ENTITY_STMNT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2043_SIGALG_NONE;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.gematik.idp.crypto.KeyUtility;
import de.gematik.idp.exceptions.IdpJoseException;
import de.gematik.idp.exceptions.IdpJwtExpiredException;
import de.gematik.idp.token.JsonWebToken;
import java.io.File;
import java.security.PublicKey;
import java.security.Security;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

@Slf4j
class EntityStatementRpTest {

  static {
    Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    Security.insertProviderAt(new BouncyCastleProvider(), 1);
  }

  @Test
  void test_verifySignature_Token1_VALID() {
    final PublicKey publicKey =
        KeyUtility.readX509PublicKey(new File("src/test/resources/keys/fachdienst-sig-pub.pem"));
    assertDoesNotThrow(
        () -> new JsonWebToken(ENTITY_STMNT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2043).verify(publicKey));
  }

  @Test
  void test_verifySignature_Token1_SigAlgNone_INVALID() {
    final PublicKey publicKey =
        KeyUtility.readX509PublicKey(new File("src/test/resources/keys/fachdienst-sig-pub.pem"));
    final JsonWebToken jwt =
        new JsonWebToken(ENTITY_STMNT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2043_SIGALG_NONE);
    assertThatThrownBy(() -> jwt.verify(publicKey)).isInstanceOf(IdpJoseException.class);
  }

  @Test
  void test_verifySignature_Token2_VALID() {
    final PublicKey publicKey =
        KeyUtility.readX509PublicKey(
            new File("src/test/resources/keys/fedmaster-sigkey-TU-pub.pem"));
    assertDoesNotThrow(
        () ->
            new JsonWebToken(ENTITY_STMNT_ABOUT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2043)
                .verify(publicKey));
  }

  @Test
  void test_verifySignature_TokenExpired_INVALID() {
    final PublicKey publicKey =
        KeyUtility.readX509PublicKey(new File("src/test/resources/keys/fachdienst-sig-pub.pem"));
    final JsonWebToken jsonWebTokenExpired = new JsonWebToken(ENTITY_STMNT_IDP_FACHDIENST_EXPIRED);
    assertThatThrownBy(() -> jsonWebTokenExpired.verify(publicKey))
        .isInstanceOf(IdpJwtExpiredException.class);
  }
}
