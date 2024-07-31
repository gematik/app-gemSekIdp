/*
 *  Copyright 2023 gematik GmbH
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

package de.gematik.idp.gsi.server.data;

import java.util.Set;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class GsiConstants {

  public static final Set<String> SCOPES_SUPPORTED =
      Set.of(
          "urn:telematik:geburtsdatum",
          "urn:telematik:alter",
          "urn:telematik:display_name",
          "urn:telematik:given_name",
          "urn:telematik:geschlecht",
          "urn:telematik:email",
          "urn:telematik:versicherter",
          "urn:telematik:family_name",
          "openid");

  public static final int IDTOKEN_TTL_MINUTES = 5;

  public static final String FEDIDP_PAR_AUTH_ENDPOINT = "/PAR_Auth";
  public static final String FED_SIGNED_JWKS_ENDPOINT = "/jws.json";
  public static final String ASSET_LINKS_ENDPOINT_ANDROID = "/.well-known/assetlinks.json";
  public static final String ASSET_LINKS_ENDPOINT_IOS = "/.well-known/apple-app-site-association";
  public static final String TLS_CLIENT_CERT_HEADER_NAME = "X-SSL-CERT";
  public static final String LOGO_URI =
      "https://raw.githubusercontent.com/gematik/zero-lab/main/static/images/GID_App_light_mode.svg";
}
