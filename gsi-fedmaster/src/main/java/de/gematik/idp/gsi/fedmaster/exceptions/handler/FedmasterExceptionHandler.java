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

package de.gematik.idp.gsi.fedmaster.exceptions.handler;

import de.gematik.idp.gsi.fedmaster.data.FedmasterErrorResponse;
import de.gematik.idp.gsi.fedmaster.exceptions.FedmasterException;
import java.time.ZonedDateTime;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
@RequiredArgsConstructor
@Slf4j
public class FedmasterExceptionHandler {

  @ExceptionHandler(FedmasterException.class)
  public ResponseEntity<FedmasterErrorResponse> handleFedmasterException(
      final FedmasterException exc) {
    final FedmasterErrorResponse body = getBody(exc);
    return new ResponseEntity<>(body, getHeader(), exc.getStatusCode());
  }

  @ExceptionHandler(MissingServletRequestParameterException.class)
  public ResponseEntity<FedmasterErrorResponse> handleMissingServletRequestParameter(
      final MissingServletRequestParameterException ex) {
    return handleFedmasterException(
        new FedmasterException(ex.getMessage(), ex, HttpStatus.BAD_REQUEST));
  }

  private HttpHeaders getHeader() {
    final HttpHeaders responseHeaders = new HttpHeaders();
    responseHeaders.add(HttpHeaders.CONTENT_TYPE, "application/json; charset=utf-8");
    responseHeaders.remove(HttpHeaders.CACHE_CONTROL);
    responseHeaders.remove(HttpHeaders.PRAGMA);
    return responseHeaders;
  }

  private FedmasterErrorResponse getBody(final FedmasterException fedmasterException) {
    return FedmasterErrorResponse.builder()
        .operation("FETCH")
        .errorMessage("invalid_request")
        .detailMessage(fedmasterException.getMessage())
        .timestamp(ZonedDateTime.now().toEpochSecond())
        .errorUuid(UUID.randomUUID().toString())
        .gematikCode(fedmasterException.getErrorCode())
        .build();
  }
}
