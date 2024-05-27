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

package de.gematik.idp.gsi.fedmaster.exceptions;

import lombok.Getter;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

@Getter
public class FedmasterException extends ResponseStatusException {

  private final String errorCode;

  public FedmasterException(final String reason, final Exception e, final HttpStatus status) {
    super(status, reason, e);
    this.errorCode = "-1";
  }

  public FedmasterException(final String reason, final HttpStatus status, final String errorCode) {
    super(status, reason);
    this.errorCode = errorCode;
  }

  public FedmasterException(final String reason, final Exception e) {
    super(HttpStatus.INTERNAL_SERVER_ERROR, reason, e);
    this.errorCode = "-1";
  }

  @Override
  public String getMessage() {
    return super.getReason();
  }
}
