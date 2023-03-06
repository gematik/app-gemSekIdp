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

package de.gematik.idp.gsi.server.exceptions;

import de.gematik.idp.data.fedidp.Oauth2ErrorCode;
import java.io.Serial;
import lombok.Getter;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

public class GsiException extends ResponseStatusException {

  @Serial private static final long serialVersionUID = -1744157595090697769L;
  @Getter private final Oauth2ErrorCode oauth2ErrorCode;

  public GsiException(final String message, final HttpStatus status) {
    super(status, message);
    this.oauth2ErrorCode = Oauth2ErrorCode.INVALID_REQUEST;
  }

  public GsiException(final Exception e) {
    super(HttpStatus.INTERNAL_SERVER_ERROR, "Runtime Error", e);
    this.oauth2ErrorCode = Oauth2ErrorCode.INVALID_REQUEST;
  }

  public GsiException(final String message, final Exception e) {
    super(HttpStatus.INTERNAL_SERVER_ERROR, message, e);
    this.oauth2ErrorCode = Oauth2ErrorCode.INVALID_REQUEST;
  }

  public GsiException(
      final String message,
      final Exception e,
      final HttpStatus status,
      final Oauth2ErrorCode oauth2ErrorCode) {
    super(status, message, e);
    this.oauth2ErrorCode = oauth2ErrorCode;
  }
}
