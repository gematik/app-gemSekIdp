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

package de.gematik.idp.gsi.test.steps;

import de.gematik.test.tiger.common.config.TigerGlobalConfiguration;
import io.cucumber.datatable.DataTable;
import io.restassured.http.ContentType;
import io.restassured.specification.RequestSpecification;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import net.serenitybdd.rest.SerenityRest;
import org.springframework.web.util.UriComponentsBuilder;

@Slf4j
public class IdpSektoralSteps {

  static final String IDP_SEKTORAL_URL = "gsiserver";
  static final String ENTITY_STATEMENT_ENDPOINT = "/.well-known/openid-federation";

  public static String replaceHostForTiger(final String url) {
    final UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(url);
    return builder.host(IDP_SEKTORAL_URL).port(null).scheme("http").toUriString();
  }

  public void fetchEntStmnt() {
    sendRequestTo("http://" + IDP_SEKTORAL_URL + ENTITY_STATEMENT_ENDPOINT, "GET", null);
  }

  public void sendRequestTo(final String url, final String httpMethod, final DataTable params) {
    final RequestSpecification reqSpec = SerenityRest.rest();
    reqSpec.redirects().follow(false);
    final Optional<String> xAuthHeaderInConfig =
        TigerGlobalConfiguration.readStringOptional("fit.xAuthHeader");
    Map<String, String> parametersMap = new HashMap<>();
    if (params != null) {
      parametersMap =
          params.transpose().cells().stream()
              .collect(
                  Collectors.toMap(
                      ele -> ele.get(0),
                      ele -> TigerGlobalConfiguration.readString(ele.get(1), ele.get(1))));
    }
    if (xAuthHeaderInConfig.isPresent()) {
      reqSpec.header("X-Auth", xAuthHeaderInConfig.orElseThrow());
    }
    if (httpMethod.equals("POST") || httpMethod.equals("PUT")) {
      reqSpec.header("Content-Type", ContentType.URLENC.withCharset("UTF-8"));
      reqSpec.formParams(parametersMap);
    } else if (httpMethod.equals("GET")) {
      if (!parametersMap.isEmpty()) {
        reqSpec.queryParams(parametersMap);
      }
    }
    reqSpec.request(httpMethod, url).thenReturn();
  }
}
