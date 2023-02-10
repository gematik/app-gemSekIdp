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

package de.gematik.idp.gsi.server.controller;

import static de.gematik.idp.IdpConstants.FED_AUTH_ENDPOINT;

import de.gematik.idp.gsi.server.ServerUrlService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.net.URISyntaxException;
import lombok.RequiredArgsConstructor;
import org.apache.http.client.utils.URIBuilder;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@RequiredArgsConstructor
public class LandingController {

  private final ServerUrlService serverUrlService;

  private static void setNoCacheHeader(final HttpServletResponse response) {
    response.setHeader("Cache-Control", "no-store");
    response.setHeader("Pragma", "no-cache");
  }

  @GetMapping(
      value = FED_AUTH_ENDPOINT,
      params = "request_uri",
      produces = MediaType.TEXT_HTML_VALUE)
  @ResponseBody
  public void redirectToLandingPage(final HttpServletRequest req, final HttpServletResponse resp)
      throws URISyntaxException {

    final String me = serverUrlService.determineServerUrl(req);
    setNoCacheHeader(resp);
    resp.setStatus(HttpStatus.FOUND.value());

    final URIBuilder redirectUriBuilder = new URIBuilder(me + "/landing.html");
    final String location = redirectUriBuilder.build().toString();
    resp.setHeader(HttpHeaders.LOCATION, location);
  }
}
