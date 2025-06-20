/*
 * Copyright (Date see Readme), gematik GmbH
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
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 */

package de.gematik.idp.gsi.server.data;

import static de.gematik.idp.gsi.server.data.GsiConstants.ACR_HIGH;
import static de.gematik.idp.gsi.server.data.GsiConstants.ACR_SUBSTANTIAL;
import static de.gematik.idp.gsi.server.util.ClaimHelper.getClaimsForScopeSet;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import de.gematik.idp.gsi.server.exceptions.GsiException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ClaimsInfoTest {

  final JsonObject validClaims = new JsonObject();

  @BeforeAll
  void setUp() {
    final JsonObject idToken = new JsonObject();

    final JsonObject amr = new JsonObject();
    final JsonArray amrValues = new JsonArray();
    amrValues.add("urn:telematik:auth:eGK");
    amr.add("values", amrValues);
    amr.addProperty("essential", true);

    final JsonObject acr = new JsonObject();
    final JsonArray acrValues = new JsonArray();
    acrValues.add(ACR_HIGH);
    acr.add("values", acrValues);
    acr.addProperty("essential", true);

    final JsonObject email = new JsonObject();
    email.addProperty("essential", true);
    final JsonObject name = new JsonObject();
    name.addProperty("essential", false);

    idToken.add("amr", amr);
    idToken.add("acr", acr);
    idToken.add("urn:telematik:claims:email", email);
    idToken.add("urn:telematik:claims:given_name", name);

    validClaims.add("id_token", idToken);
  }

  @Test
  void test_constructor_VALID() {
    assertDoesNotThrow(() -> new ClaimsInfo(validClaims.toString()));
  }

  @Test
  void test_constructor_onlyAcrIsEssential_VALID() {

    final JsonObject validClaimsAcrEssential = validClaims.deepCopy();
    validClaimsAcrEssential.getAsJsonObject("id_token").getAsJsonObject("amr").remove("essential");
    assertDoesNotThrow(() -> new ClaimsInfo(validClaimsAcrEssential.toString()));
  }

  @Test
  void test_constructor_multipleAcrAndAmrValues_VALID() {
    final JsonObject validClaimsMultipleAcrAmrValues = validClaims.deepCopy();
    validClaimsMultipleAcrAmrValues
        .getAsJsonObject("id_token")
        .getAsJsonObject("amr")
        .addProperty("value", "urn:telematik:auth:mEW");
    validClaimsMultipleAcrAmrValues
        .getAsJsonObject("id_token")
        .getAsJsonObject("acr")
        .addProperty("value", ACR_SUBSTANTIAL);
    assertDoesNotThrow(() -> new ClaimsInfo(validClaimsMultipleAcrAmrValues.toString()));
  }

  @Test
  void test_constructor_claimsIsNull_VALID() {
    assertDoesNotThrow(() -> new ClaimsInfo(null));
  }

  @Test
  void test_constructor_claimsIsEmpty_VALID() {
    assertDoesNotThrow(() -> new ClaimsInfo(""));
  }

  @Test
  void test_constructor_claimsShouldNotHaveValues_INVALID() {

    final JsonObject invalidClaims = validClaims.deepCopy();
    invalidClaims
        .getAsJsonObject("id_token")
        .getAsJsonObject("urn:telematik:claims:given_name")
        .addProperty("value", "anyName");
    assertThatThrownBy(() -> new ClaimsInfo(invalidClaims.toString()))
        .isInstanceOf(GsiException.class)
        .hasMessageContaining(
            "claim urn:telematik:claims:given_name should not have value or values set");
  }

  @Test
  void test_constructor_invalidClaimName_INVALID() {

    final JsonObject invalidClaims = validClaims.deepCopy();
    invalidClaims.getAsJsonObject("id_token").addProperty("invalidClaimName", "anything");
    assertThatThrownBy(() -> new ClaimsInfo(invalidClaims.toString()))
        .isInstanceOf(GsiException.class)
        .hasMessageContaining("claim invalidClaimName is not supported");
  }

  @Test
  void test_constructor_claimsIsNotAJsonObject_INVALID() {

    assertThatThrownBy(() -> new ClaimsInfo("invalidJsonStruct"))
        .isInstanceOf(GsiException.class)
        .hasMessageContaining("parameter claims is not a JSON object");
  }

  @Test
  void test_constructor_paramJsonButNotClaims_INVALID() {
    final JsonObject noClaimsObject = new JsonObject();
    noClaimsObject.addProperty("invalid", "any");

    assertThatThrownBy(() -> new ClaimsInfo(noClaimsObject.toString()))
        .isInstanceOf(GsiException.class)
        .hasMessageContaining("parameter claims has invalid structure");
  }

  @Test
  void test_constructor_invalidAcrValue_INVALID() {
    final JsonObject invalidClaims = validClaims.deepCopy();
    invalidClaims
        .getAsJsonObject("id_token")
        .getAsJsonObject("acr")
        .getAsJsonArray("values")
        .add("invalid-acr-value");

    assertThatThrownBy(() -> new ClaimsInfo(invalidClaims.toString()))
        .isInstanceOf(GsiException.class)
        .hasMessageContaining("invalid acr value: invalid-acr-value");
  }

  @Test
  void test_constructor_invalidAmrValue_INVALID() {
    final JsonObject invalidClaims = validClaims.deepCopy();
    invalidClaims
        .getAsJsonObject("id_token")
        .getAsJsonObject("amr")
        .getAsJsonArray("values")
        .add("invalid:amr:value");

    assertThatThrownBy(() -> new ClaimsInfo(invalidClaims.toString()))
        .isInstanceOf(GsiException.class)
        .hasMessageContaining("invalid amr value: invalid:amr:value");
  }

  @Test
  void test_constructor_invalidAcrAmrCombination_acrSubstantial_INVALID() {
    final JsonObject invalidClaims = validClaims.deepCopy();
    final JsonArray acr =
        invalidClaims.getAsJsonObject("id_token").getAsJsonObject("acr").getAsJsonArray("values");
    acr.remove(0);
    acr.add(ACR_SUBSTANTIAL);
    final JsonArray amr =
        invalidClaims.getAsJsonObject("id_token").getAsJsonObject("amr").getAsJsonArray("values");
    amr.add("urn:telematik:auth:mEW");

    assertThatThrownBy(() -> new ClaimsInfo(invalidClaims.toString()))
        .isInstanceOf(GsiException.class)
        .hasMessageContaining("invalid combination of essential values acr and amr");
  }

  @Test
  void test_constructor_invalidAcrAmrCombination_acrHigh_INVALID() {
    final JsonObject invalidClaims = validClaims.deepCopy();
    invalidClaims
        .getAsJsonObject("id_token")
        .getAsJsonObject("amr")
        .getAsJsonArray("values")
        .add("urn:telematik:auth:mEW");

    assertThatThrownBy(() -> new ClaimsInfo(invalidClaims.toString()))
        .isInstanceOf(GsiException.class)
        .hasMessageContaining("invalid combination of essential values acr and amr");
  }

  @Test
  void test_constructor_invalidAcrAmrCombinationButNotEssential_VALID() {
    final JsonObject validClaimsInvalidCombo = validClaims.deepCopy();
    final JsonObject amr =
        validClaimsInvalidCombo.getAsJsonObject("id_token").getAsJsonObject("amr");
    amr.getAsJsonArray("values").add("urn:telematik:auth:mEW");
    amr.remove("essential");

    assertDoesNotThrow(() -> new ClaimsInfo(validClaimsInvalidCombo.toString()));
  }

  @Test
  void test_addClaimsFromScopeToClaimsSet_VALID() {

    final ClaimsInfo validClaimsInfo = new ClaimsInfo(validClaims.toString());

    assertThat(validClaimsInfo.getEssentialClaims())
        .containsExactlyInAnyOrder("urn:telematik:claims:email");
    assertThat(validClaimsInfo.getOptionalClaims())
        .containsExactlyInAnyOrder("urn:telematik:claims:given_name");
    assertThat(validClaimsInfo.getAcrValues()).containsExactlyInAnyOrder(ACR_HIGH);
    assertThat(validClaimsInfo.getAmrValues()).containsExactlyInAnyOrder("urn:telematik:auth:eGK");

    final Set<String> claimsFromScope =
        getClaimsForScopeSet(
            new HashSet<>(
                Arrays.asList(
                    "urn:telematik:family_name",
                    "urn:telematik:display_name",
                    "urn:telematik:given_name")));
    validClaimsInfo.addClaimsFromScopeToClaimsSet(claimsFromScope);

    assertThat(validClaimsInfo.getEssentialClaims())
        .containsExactlyInAnyOrder("urn:telematik:claims:email");
    assertThat(validClaimsInfo.getOptionalClaims())
        .containsExactlyInAnyOrder(
            "urn:telematik:claims:given_name",
            "urn:telematik:claims:family_name",
            "urn:telematik:claims:display_name");
    assertThat(validClaimsInfo.getAcrValues()).containsExactlyInAnyOrder(ACR_HIGH);
    assertThat(validClaimsInfo.getAmrValues()).containsExactlyInAnyOrder("urn:telematik:auth:eGK");
  }
}
