package de.gematik.idp.gsi.server.data;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class GsiConstants {
  public static final Set<String> SCOPES_SUPPORTED =
      new HashSet<>(
          Arrays.asList(
              "urn:telematik:geburtsdatum",
              "urn:telematik:alter",
              "urn:telematik:display_name",
              "urn:telematik:given_name",
              "urn:telematik:geschlecht",
              "urn:telematik:email",
              "urn:telematik:versicherter",
              "openid"));
}
