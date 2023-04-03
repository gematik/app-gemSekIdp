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

import static de.gematik.idp.gsi.test.steps.IdpSektoralSteps.replaceHostForTiger;
import static org.assertj.core.api.Assertions.assertThat;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import de.gematik.rbellogger.RbelLogger;
import de.gematik.rbellogger.data.RbelElement;
import de.gematik.rbellogger.data.facet.RbelJsonFacet;
import de.gematik.rbellogger.data.facet.RbelJwtFacet;
import de.gematik.test.tiger.common.config.TigerGlobalConfiguration;
import de.gematik.test.tiger.lib.TigerDirector;
import de.gematik.test.tiger.lib.json.JsonChecker;
import io.cucumber.datatable.DataTable;
import io.cucumber.java.en.And;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import net.serenitybdd.rest.SerenityRest;
import net.thucydides.core.annotations.Steps;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.lang.JoseException;

@Slf4j
public class StepsGlue {

  private static final List<JsonElement> truststore = new ArrayList<>();

  @Steps IdpSektoralSteps idpSektoralSteps;

  @And("Fetch Entity statement")
  public void ifetchEntStmnt() {
    idpSektoralSteps.fetchEntStmnt();
  }

  @When("Send Get Request to {string}")
  public void sendGetRequestTo(final String url) {
    idpSektoralSteps.sendRequestTo(
        replaceHostForTiger(TigerGlobalConfiguration.resolvePlaceholders(url)), "GET", null);
  }

  @When("Send Get Request to {string} with")
  public void sendGetRequestTo(final String url, final DataTable params) {
    idpSektoralSteps.sendRequestTo(
        replaceHostForTiger(TigerGlobalConfiguration.resolvePlaceholders(url)), "GET", params);
  }

  @When("Send Post Request to {string} with")
  public void sendPostRequestTo(final String url, final DataTable params) {
    idpSektoralSteps.sendRequestTo(
        replaceHostForTiger(TigerGlobalConfiguration.resolvePlaceholders(url)), "POST", params);
  }

  @When("Send Post Request with invalid Client Cert to {string} with")
  public void sendPostRequestViaTigerProxyInvalidCertTo(final String url, final DataTable params) {
    SerenityRest.proxy(
        "127.0.0.1",
        Integer.valueOf(TigerGlobalConfiguration.readString("tiger.ports.invalidCertPort")));
    SerenityRest.useRelaxedHTTPSValidation();
    idpSektoralSteps.sendRequestTo(
        TigerGlobalConfiguration.resolvePlaceholders(url), "POST", params);
  }

  @And("Expect JWKS in last message and add its keys to truststore")
  public void findJwk() {
    final RbelElement lastMessage = getLastMessage();
    final JsonArray jwks =
        (JsonArray)
            lastMessage
                .findElement("$..keys")
                .flatMap(el -> el.getFacet(RbelJsonFacet.class))
                .map(RbelJsonFacet::getJsonElement)
                .orElseThrow();
    assertThat(jwks).isNotEmpty();
    for (final JsonElement jwk : jwks) {
      truststore.add(jwk);
    }
  }

  @SneakyThrows
  @Then("Check signature of JWS in last message")
  public void checkSignature() {
    final RbelElement jwsBody = getLastMessage().findElement("$.body").orElseThrow();
    final String jwsAsString = jwsBody.getRawStringContent();
    final String kidInJws =
        jwsBody
            .getFacet(RbelJwtFacet.class)
            .orElseThrow()
            .getHeader()
            .getFacetOrFail(RbelJsonFacet.class)
            .getJsonElement()
            .getAsJsonObject()
            .get("kid")
            .getAsString();
    final JsonWebKey jwk = getJsonWebKey(truststore, kidInJws);
    validateJwsSignature(jwsAsString, jwk);
  }

  @Then("Json String {string} at {string} matches:")
  public void jsonStringMatches(
      final String jsonString, final String rbelPath, final String oracleDocStr) {
    final RbelLogger rbelLogger = RbelLogger.build();
    final RbelElement rbelElement =
        rbelLogger
            .getRbelConverter()
            .convertElement(TigerGlobalConfiguration.readString(jsonString, jsonString), null);
    new JsonChecker()
        .compareJsonStrings(
            rbelElement.findElement(rbelPath).orElseThrow().getRawStringContent(),
            oracleDocStr,
            false);
  }

  static void validateJwsSignature(final String jws, final JsonWebKey jwk)
      throws InvalidJwtException {
    final JwtConsumer jwtConsumer =
        new JwtConsumerBuilder()
            .setVerificationKey(jwk.getKey())
            .setSkipDefaultAudienceValidation()
            .build();
    jwtConsumer.process(jws);
  }

  static JsonWebKey getJsonWebKey(final List<JsonElement> keyList, final String kid)
      throws JoseException {
    final JsonElement keyAsJwk =
        keyList.stream()
            .map(JsonElement::getAsJsonObject)
            .filter(el -> el.get("kid").getAsString().equals(kid))
            .findFirst()
            .orElseThrow();
    final Map keyAsMap = new Gson().fromJson(keyAsJwk, Map.class);
    return JsonWebKey.Factory.newJwk(keyAsMap);
  }

  private static RbelElement getLastMessage() {
    final Deque<RbelElement> rbelMessages =
        TigerDirector.getTigerTestEnvMgr().getLocalTigerProxyOrFail().getRbelMessages();
    return rbelMessages.getLast();
  }
}
