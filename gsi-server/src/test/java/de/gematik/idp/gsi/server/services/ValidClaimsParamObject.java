/*
 * Copyright (Change Date see Readme), gematik GmbH
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

package de.gematik.idp.gsi.server.services;

import static de.gematik.idp.gsi.server.data.GsiConstants.ACR_HIGH;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

public class ValidClaimsParamObject {
  public static JsonObject getValidClaimsParameterObject() {
    final JsonObject idTokenClaims = new JsonObject();

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
    email.addProperty("essential", false);
    final JsonObject name = new JsonObject();
    name.addProperty("essential", true);

    idTokenClaims.add("amr", amr);
    idTokenClaims.add("acr", acr);
    idTokenClaims.add("urn:telematik:claims:email", email);
    idTokenClaims.add("urn:telematik:claims:given_name", name);

    final JsonObject claims = new JsonObject();
    claims.add("id_token", idTokenClaims);
    return claims;
  }
}
