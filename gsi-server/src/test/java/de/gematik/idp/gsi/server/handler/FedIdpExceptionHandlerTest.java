/*
 * Copyright (c) 2023 gematik GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an 'AS IS' BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.idp.gsi.server.handler;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import de.gematik.idp.data.fedidp.Oauth2ErrorCode;
import de.gematik.idp.data.fedidp.Oauth2ErrorResponse;
import de.gematik.idp.gsi.server.exceptions.GsiException;
import de.gematik.idp.gsi.server.exceptions.handler.GsiExceptionHandler;
import jakarta.validation.ValidationException;
import java.util.Objects;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MissingServletRequestParameterException;

class FedIdpExceptionHandlerTest {

  private final GsiExceptionHandler fedIdpExceptionHandler = new GsiExceptionHandler();

  @Test
  void testGsiException() {
    final ResponseEntity<Oauth2ErrorResponse> resp =
        fedIdpExceptionHandler.handleGsiException(
            new GsiException(
                Oauth2ErrorCode.INVALID_REQUEST,
                "something strange happened",
                HttpStatus.INSUFFICIENT_STORAGE));
    assertThat(Objects.requireNonNull(resp.getBody()).getError())
        .isEqualTo(Oauth2ErrorCode.INVALID_REQUEST);
  }

  @Test
  void testValidationException() {
    final ResponseEntity<Oauth2ErrorResponse> resp =
        fedIdpExceptionHandler.handleValidationException(
            new ValidationException("something strange happened again"));
    assertThat(Objects.requireNonNull(resp.getBody()).getError())
        .isEqualTo(Oauth2ErrorCode.INVALID_REQUEST);
  }

  @Test
  void testMissingServletRequestParameterException() {
    final ResponseEntity<Oauth2ErrorResponse> resp =
        fedIdpExceptionHandler.handleMissingServletRequestParameter(
            new MissingServletRequestParameterException("anyName", "anyType"));
    assertThat(Objects.requireNonNull(resp.getBody()).getError())
        .isEqualTo(Oauth2ErrorCode.INVALID_REQUEST);
  }

  @Test
  void testRuntimeException() {
    final ResponseEntity<Oauth2ErrorResponse> resp =
        fedIdpExceptionHandler.handleRuntimeException(new RuntimeException("anyMsg"));
    assertThat(Objects.requireNonNull(resp.getBody()).getError())
        .isEqualTo(Oauth2ErrorCode.INVALID_REQUEST);
  }

  @Test
  void testGsiExceptionWithEx() {
    final ResponseEntity<Oauth2ErrorResponse> resp =
        fedIdpExceptionHandler.handleGsiException(new GsiException(new NullPointerException()));
    assertThat(resp.getStatusCode().is5xxServerError()).isTrue();
  }

  @Test
  void testGsiExceptionWithExAndMsg() {
    final ResponseEntity<Oauth2ErrorResponse> resp =
        fedIdpExceptionHandler.handleGsiException(
            new GsiException("Oooops", new NullPointerException()));
    assertThat(resp.getStatusCode().is5xxServerError()).isTrue();
  }
}
