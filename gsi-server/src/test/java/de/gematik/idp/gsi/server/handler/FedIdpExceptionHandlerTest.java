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

import de.gematik.idp.data.fedidp.FedIdpErrorResponse;
import de.gematik.idp.gsi.server.exceptions.GsiException;
import de.gematik.idp.gsi.server.exceptions.handler.GsiExceptionHandler;
import jakarta.validation.ValidationException;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MissingServletRequestParameterException;

class FedIdpExceptionHandlerTest {

  private final GsiExceptionHandler fedIdpExceptionHandler = new GsiExceptionHandler();

  @Test
  void testIdpSektoralException() {
    final ResponseEntity<FedIdpErrorResponse> resp =
        fedIdpExceptionHandler.handleGsiException(
            new GsiException("something strange happened", HttpStatus.INSUFFICIENT_STORAGE));
    assertThat(resp.toString()).isNotEmpty();
  }

  @Test
  void testValidationException() {
    final ResponseEntity<FedIdpErrorResponse> resp =
        fedIdpExceptionHandler.handleValidationException(
            new ValidationException("something strange happened again"));
    assertThat(resp.toString()).isNotEmpty();
  }

  @Test
  void testMissingServletRequestParameterException() {
    final ResponseEntity<FedIdpErrorResponse> resp =
        fedIdpExceptionHandler.handleMissingServletRequestParameter(
            new MissingServletRequestParameterException("anyName", "anyType"));
    assertThat(resp.toString()).isNotEmpty();
  }

  @Test
  void testRuntimeException() {
    final ResponseEntity<FedIdpErrorResponse> resp =
        fedIdpExceptionHandler.handleRuntimeException(new RuntimeException("anyMsg"));
    assertThat(resp.toString()).isNotEmpty();
  }

  @Test
  void testGsiExceptionWithEx() {
    final ResponseEntity<FedIdpErrorResponse> resp =
        fedIdpExceptionHandler.handleGsiException(new GsiException(new NullPointerException()));
    assertThat(resp.getStatusCode().is5xxServerError());
  }

  @Test
  void testGsiExceptionWithExAndMsg() {
    final ResponseEntity<FedIdpErrorResponse> resp =
        fedIdpExceptionHandler.handleGsiException(
            new GsiException("Oooops", new NullPointerException()));
    assertThat(resp.getStatusCode().is5xxServerError());
  }
}
