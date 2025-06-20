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

import static de.gematik.idp.data.Oauth2ErrorCode.INVALID_REQUEST;
import static de.gematik.idp.gsi.server.data.GsiConstants.VALID_CLAIMS;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import de.gematik.idp.gsi.server.exceptions.GsiException;
import de.gematik.idp.gsi.server.services.RequestValidator;
import java.util.HashSet;
import java.util.Set;
import lombok.*;
import org.springframework.http.HttpStatus;

@Getter
@NoArgsConstructor
public class ClaimsInfo {
  private final Set<String> amrValues = new HashSet<>();
  private final Set<String> acrValues = new HashSet<>();
  private final Set<String> essentialClaims = new HashSet<>();
  private final Set<String> optionalClaims = new HashSet<>();

  public ClaimsInfo(final String claims) {
    if (claims == null || claims.isEmpty()) return;
    try {
      final JsonObject claimsForIdToken =
          JsonParser.parseString(claims).getAsJsonObject().getAsJsonObject("id_token");
      if (claimsForIdToken == null) {
        throw new GsiException(
            INVALID_REQUEST, "parameter claims has invalid structure", HttpStatus.BAD_REQUEST);
      }
      setAmrAcrSets(claimsForIdToken);
      setClaimSets(claimsForIdToken);
    } catch (JsonSyntaxException | IllegalStateException | NullPointerException e) {
      throw new GsiException(
          INVALID_REQUEST, "parameter claims is not a JSON object", HttpStatus.BAD_REQUEST);
    }
  }

  public void addClaimsFromScopeToClaimsSet(final Set<String> claimSetFromScope) {
    claimSetFromScope.forEach(
        claim -> {
          if (!essentialClaims.contains(claim)) {
            optionalClaims.add(claim);
          }
        });
  }

  private void setAmrAcrSets(final JsonObject claimsForIdToken) {
    setValueIfEssential(claimsForIdToken.get("amr"), amrValues);
    setValueIfEssential(claimsForIdToken.get("acr"), acrValues);
    RequestValidator.validateAmrAcrCombination(acrValues, amrValues);
  }

  private void setClaimSets(final JsonObject claimsForIdToken) {
    claimsForIdToken.entrySet().stream()
        .filter(
            claimEntry -> !(claimEntry.getKey().equals("amr") || claimEntry.getKey().equals("acr")))
        .forEach(
            claimEntry -> {
              final String claimName = claimEntry.getKey();
              if (!VALID_CLAIMS.contains(claimName)) {
                throw new GsiException(
                    INVALID_REQUEST,
                    "claim " + claimName + " is not supported",
                    HttpStatus.BAD_REQUEST);
              }
              final JsonObject subClaims = claimEntry.getValue().getAsJsonObject();
              final JsonElement claimIsEssential = subClaims.get("essential");
              final JsonElement value = subClaims.get("value");
              final JsonElement values = subClaims.get("values");
              if (value != null || values != null) {
                throw new GsiException(
                    INVALID_REQUEST,
                    "claim " + claimName + " should not have value or values set",
                    HttpStatus.BAD_REQUEST);
              }
              if (claimIsEssential != null && claimIsEssential.getAsBoolean()) {
                essentialClaims.add(claimName);
              } else {
                optionalClaims.add(claimName);
              }
            });
  }

  private void setValueIfEssential(final JsonElement claim, final Set<String> claimSet) {
    if (claim == null) return;
    final JsonObject claimObject = claim.getAsJsonObject();
    final JsonElement isEssential = claimObject.get("essential");
    if (isEssential != null && isEssential.getAsBoolean()) {
      final JsonElement value = claimObject.get("value");
      final JsonElement values = claimObject.get("values");
      if (value != null) {
        claimSet.add(value.getAsString());
      } else if (values != null) {
        values.getAsJsonArray().asList().forEach(v -> claimSet.add(v.getAsString()));
      }
    }
  }
}
