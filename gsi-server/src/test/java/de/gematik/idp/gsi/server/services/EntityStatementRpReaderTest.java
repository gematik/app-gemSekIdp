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

package de.gematik.idp.gsi.server.services;

import static de.gematik.idp.gsi.server.common.Constants.ENTITY_STMNT_FACHDIENST_WITH_OPTIONAL_JWKS;
import static de.gematik.idp.gsi.server.common.Constants.ENTITY_STMNT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2043;
import static de.gematik.idp.gsi.server.common.Constants.SIGNED_JWKS;
import static de.gematik.idp.gsi.server.common.Constants.SIGNED_JWKS_TWO_CERTS;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;

import de.gematik.idp.gsi.server.exceptions.GsiException;
import de.gematik.idp.token.JsonWebToken;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

class EntityStatementRpReaderTest {

  private static final JsonWebToken VALID_ENTITY_STMNT =
      new JsonWebToken(ENTITY_STMNT_IDP_FACHDIENST_EXPIRES_IN_YEAR_2043);

  private static final String ENTITY_STATEMENT_WITH_CERT =
      "eyJ0eXAiOiJlbnRpdHktc3RhdGVtZW50K2p3dCIsImtpZCI6InB1a19pZHBfc2lnX3NlayIsImFsZyI6IkVTMjU2In0.eyJpc3MiOiJodHRwczovL2lkcC10ZXN0LmFwcC50aS1kaWVuc3RlLmRlIiwic3ViIjoiaHR0cHM6Ly9pZHAtdGVzdC5hcHAudGktZGllbnN0ZS5kZSIsImlhdCI6MTcyNDc4ODA3MiwiZXhwIjoxNzI0ODc0NDcyLCJqd2tzIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiV2JPWk9hS01uaWVIaFRzbk1TdlFNZUh6dDR4U1V3YlRMdWRjQTVseVV3WSIsInkiOiJXVmN5UFVvU3FWMFp1MFJQcC00NU5kZWJ1YURVLWVZbjRqTk9fN2k2QzJjIiwia2lkIjoicHVrX2lkcF9zaWdfc2VrIiwidXNlIjoic2lnIiwiYWxnIjoiRVMyNTYifV19LCJhdXRob3JpdHlfaGludHMiOlsiaHR0cHM6Ly9hcHAtdGVzdC5mZWRlcmF0aW9ubWFzdGVyLmRlIl0sIm1ldGFkYXRhIjp7Im9wZW5pZF9yZWx5aW5nX3BhcnR5Ijp7Imp3a3MiOnsia2V5cyI6W3sia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJXNTVqWTRZR3QtaDZ5M1pDbTRoVEJudWUzM21GaHA4S3Q2WW80SFJtdkFNIiwieSI6IlRhd01vQWVGck0wRUNQMGQxVkdJTFJwTVd1TTNpZVFidU1ZTmZ4enJWeEkiLCJraWQiOiJwdWtfaWRwX2VuY19zZWsiLCJ1c2UiOiJlbmMiLCJhbGciOiJFQ0RILUVTIn0seyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6Il96TF85ZGptMEJFUFFRdXBfZjBrTHN5WHZNRVhhd0s4alB1VE1UMThJNHciLCJ5IjoidnVGUW16RkdKYWVVdzl2a2ZnWnVCUDdsTzJOSmpHcHkwZ2wwd0tDd2NhRSIsInVzZSI6InNpZyIsImFsZyI6IkVTMjU2IiwieDVjIjpbIk1JSUJvRENDQVVXZ0F3SUJBZ0lVRnN2a1hNQ1Azc2hUbUJtVWE2SC9wMmxXWTVZd0NnWUlLb1pJemowRUF3SXdKVEVqTUNFR0ExVUVBd3dhYVdSd0xYUmxjM1F1WVhCd0xuUnBMV1JwWlc1emRHVXVaR1V3SGhjTk1qTXdPREUyTVRFeU56QXdXaGNOTWpRd09URTNNVEV5TnpBd1dqQWxNU013SVFZRFZRUUREQnBwWkhBdGRHVnpkQzVoY0hBdWRHa3RaR2xsYm5OMFpTNWtaVEJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCUDh5Ly9YWTV0QVJEMEVMcWYzOUpDN01sN3pCRjJzQ3ZJejdrekU5ZkNPTXZ1RlFtekZHSmFlVXc5dmtmZ1p1QlA3bE8yTkpqR3B5MGdsMHdLQ3djYUdqVXpCUk1CMEdBMVVkRGdRV0JCUUtSRm9mZUpPeTI1cUwrTG55VERSTzlEVlFBREFmQmdOVkhTTUVHREFXZ0JRS1JGb2ZlSk95MjVxTCtMbnlURFJPOURWUUFEQVBCZ05WSFJNQkFmOEVCVEFEQVFIL01Bb0dDQ3FHU000OUJBTUNBMGtBTUVZQ0lRRFFWVnFqT2RDN21zb28rMG9UQWNlaUZqVXlEb3FwYTBBZjRyQjdHNEhiaUFJaEFQcjlDaWJGOFZrNGNOaHRKWUZBSU9aQXJnRGFWbXhmZHVkckRZSkFBOVhJIl0sImtpZCI6IklFR3F1cUMzSkpIT2tPLTRHdU93aHZGNF9FQldpNEFHdXQ4cTYxZDM4REUifV19LCJjbGllbnRfbmFtZSI6IkUtUmV6ZXB0IEFwcCIsInJlZGlyZWN0X3VyaXMiOlsiaHR0cHM6Ly9hcHBsaW5rLXRlc3QudGsuZGUvZXJlemVwdC9yZWRpcmVjdEZyb21BdXRoZW50aWNhdG9yIiwiaHR0cHM6Ly9kYXMtZS1yZXplcHQtZnVlci1kZXV0c2NobGFuZC5kZS9leHRhdXRoIiwiaHR0cHM6Ly9pZGJyb2tlci5hb2tidy5ydS5ub25wcm9kLWVoZWFsdGgtaWQuZGUvZXJwL2xvZ2luIiwiaHR0cHM6Ly9pZGJyb2tlci5hb2twbC5ydS5ub25wcm9kLWVoZWFsdGgtaWQuZGUvZXJwL2xvZ2luIiwiaHR0cHM6Ly9pZGJyb2tlci5pYm0udHUubm9ucHJvZC1laGVhbHRoLWlkLmRlL2VycC9sb2dpbiIsImh0dHBzOi8vcmVkaXJlY3QuZ2VtYXRpay5kZS9lcmV6ZXB0IiwiaHR0cHM6Ly90dS5yaXNlLWVwYS5kZS9lcmV6ZXB0Il0sInJlc3BvbnNlX3R5cGVzIjpbImNvZGUiXSwiY2xpZW50X3JlZ2lzdHJhdGlvbl90eXBlcyI6WyJhdXRvbWF0aWMiXSwiZ3JhbnRfdHlwZXMiOlsiYXV0aG9yaXphdGlvbl9jb2RlIl0sInJlcXVpcmVfcHVzaGVkX2F1dGhvcml6YXRpb25fcmVxdWVzdHMiOnRydWUsInRva2VuX2VuZHBvaW50X2F1dGhfbWV0aG9kIjoic2VsZl9zaWduZWRfdGxzX2NsaWVudF9hdXRoIiwiZGVmYXVsdF9hY3JfdmFsdWVzIjpbImdlbWF0aWstZWhlYWx0aC1sb2EtaGlnaCJdLCJpZF90b2tlbl9zaWduZWRfcmVzcG9uc2VfYWxnIjoiRVMyNTYiLCJpZF90b2tlbl9lbmNyeXB0ZWRfcmVzcG9uc2VfYWxnIjoiRUNESC1FUyIsImlkX3Rva2VuX2VuY3J5cHRlZF9yZXNwb25zZV9lbmMiOiJBMjU2R0NNIiwic2NvcGUiOiJvcGVuaWQgdXJuOnRlbGVtYXRpazpkaXNwbGF5X25hbWUgdXJuOnRlbGVtYXRpazp2ZXJzaWNoZXJ0ZXIifX19.zUhIP91srHWXfuuGMCGPlP7uKUQnhnL-orKAdifCPEnUmv9JLdPiRmRkLI7_pXqVuR8UCQMF2vi50QT6NkwA5w";

  private static final String SIGNED_JWKS_WITHOUT_CERT =
      "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InB1a19mZF9zaWcifQ.ewogICJpc3MiOiAiaHR0cHM6Ly9pZHBmYWRpLmRldi5nZW1hdGlrLnNvbHV0aW9ucyIsCiAgImlhdCI6IDE2OTcyMDI0ODgsCiAgImtleXMiOiBbCiAgICB7CiAgICAgICJ1c2UiOiAic2lnIiwKICAgICAgImtpZCI6ICJwdWtfZmRfc2lnIiwKICAgICAgImt0eSI6ICJFQyIsCiAgICAgICJjcnYiOiAiUC0yNTYiLAogICAgICAieCI6ICI5YkpzMjdZQWZsTVVXSzVueHVpRjZYQUcwSmF6dXZ3UmkxRXBGSzBYS2lrIiwKICAgICAgInkiOiAiUDhsek5WUk9nVHV3YkRxc2Q4clQxQUkzemV6OTRIQnNURHBPdmFqUDByWSIKICAgIH0sCiAgICB7CiAgICAgICJ1c2UiOiAiZW5jIiwKICAgICAgImtpZCI6ICJwdWtfZmRfZW5jIiwKICAgICAgImt0eSI6ICJFQyIsCiAgICAgICJjcnYiOiAiUC0yNTYiLAogICAgICAieCI6ICJOUUxhV2J1UURIZ1NIYWhxYjl6eGxEZGlNQ0hYU2dZMEw5cWwxazdCVlVFIiwKICAgICAgInkiOiAiX1VTZ21xaGxNM3B2YWJrWjJTU19ZRTJRNTd0VHM2cEs5Y0VfdVpCLXUzYyIKICAgIH0KICBdCn0=.BYCS-xn-jSpIFq501Jb7B0kewaO7UeOrg7LJmCLyQI3xz76rXJ7PiDtBTyAeTQ1S5jyQfS_-t2oDtWv5UJQh3w";
  private static final String SIGNED_JWKS_WITHOUT_ENCKEY =
      "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InB1a19mZF9zaWcifQ.ewogICJpc3MiOiAiaHR0cHM6Ly9pZHBmYWRpLmRldi5nZW1hdGlrLnNvbHV0aW9ucyIsCiAgImlhdCI6IDE2OTcyMDI0ODgsCiAgImtleXMiOiBbCiAgICB7CiAgICAgICJ1c2UiOiAic2lnIiwKICAgICAgImtpZCI6ICJwdWtfZmRfc2lnIiwKICAgICAgImt0eSI6ICJFQyIsCiAgICAgICJjcnYiOiAiUC0yNTYiLAogICAgICAieCI6ICI5YkpzMjdZQWZsTVVXSzVueHVpRjZYQUcwSmF6dXZ3UmkxRXBGSzBYS2lrIiwKICAgICAgInkiOiAiUDhsek5WUk9nVHV3YkRxc2Q4clQxQUkzemV6OTRIQnNURHBPdmFqUDByWSIKICAgIH0sCiAgICB7CiAgICAgICJ4NWMiOiBbCiAgICAgICAgIk1JSUNHakNDQWNDZ0F3SUJBZ0lVVEd5TG0wZFhDU3dVdW5TK0M3WTRkclpnRzVrd0NnWUlLb1pJemowRUF3SXdmekVMTUFrR0ExVUVCaE1DUkVVeER6QU5CZ05WQkFnTUJrSmxjbXhwYmpFUE1BMEdBMVVFQnd3R1FtVnliR2x1TVJvd0dBWURWUVFLREJGblpXMWhkR2xySUU1UFZDMVdRVXhKUkRFUE1BMEdBMVVFQ3d3R1VGUWdTVVJOTVNFd0h3WURWUVFEREJobVlXTm9aR2xsYm5OMFZHeHpReUJVUlZOVUxVOU9URmt3SGhjTk1qTXdNakV3TVRJek5UTTFXaGNOTWpRd01qRXdNVEl6TlRNMVdqQi9NUXN3Q1FZRFZRUUdFd0pFUlRFUE1BMEdBMVVFQ0F3R1FtVnliR2x1TVE4d0RRWURWUVFIREFaQ1pYSnNhVzR4R2pBWUJnTlZCQW9NRVdkbGJXRjBhV3NnVGs5VUxWWkJURWxFTVE4d0RRWURWUVFMREFaUVZDQkpSRTB4SVRBZkJnTlZCQU1NR0daaFkyaGthV1Z1YzNSVWJITkRJRlJGVTFRdFQwNU1XVEJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCT1JxcVN1cisySFpUaEZxQTdFR3E4YmJGMi81d0w1bWpjL0J4b09kb3Q3cnQwUUwwRG5LMjBlcjRwS1R4cml5MCtOUHN4UUZrdm1LZUVLYlY0RWlKNlNqR2pBWU1Ba0dBMVVkRXdRQ01BQXdDd1lEVlIwUEJBUURBZ1hnTUFvR0NDcUdTTTQ5QkFNQ0EwZ0FNRVVDSUQwVGl2VitubFROMDZ2akJadDFQVVFkNkdoUWtheUVKK2FEcVMwUjJaL3hBaUVBMUt4RkhRN0dMRFNsLzZPb2dXRnN4S2FmWFEreVpLazl2dEsvUG9oZm0zbz0iCiAgICAgIF0sCiAgICAgICJ1c2UiOiAic2lnIiwKICAgICAgImtpZCI6ICJwdWtfdGxzX3NpZyIsCiAgICAgICJrdHkiOiAiRUMiLAogICAgICAiY3J2IjogIlAtMjU2IiwKICAgICAgIngiOiAiNUdxcEs2djdZZGxPRVdvRHNRYXJ4dHNYYl9uQXZtYU56OEhHZzUyaTN1cyIsCiAgICAgICJ5IjogInQwUUwwRG5LMjBlcjRwS1R4cml5MC1OUHN4UUZrdm1LZUVLYlY0RWlKNlEiCiAgICB9CiAgXQp9.BYCS-xn-jSpIFq501Jb7B0kewaO7UeOrg7LJmCLyQI3xz76rXJ7PiDtBTyAeTQ1S5jyQfS_-t2oDtWv5UJQh3w";

  private static final String ENTITY_STMNT_MISSING_CLAIM_REDIRECT_URIS =
      "eyJhbGciOiJFUzI1NiIsInR5cCI6ImVudGl0eS1zdGF0ZW1lbnQrand0Iiwia2lkIjoicHVrX2ZkX3NpZyJ9.ewogICJpc3MiOiAiaHR0cDovL2xvY2FsaG9zdDo4MDg0IiwKICAic3ViIjogImh0dHA6Ly9sb2NhbGhvc3Q6ODA4NCIsCiAgImlhdCI6IDE3MDIwNTA0NTEsCiAgImV4cCI6IDIzMzMyMDI0NTEsCiAgImp3a3MiOiB7CiAgICAia2V5cyI6IFsKICAgICAgewogICAgICAgICJ1c2UiOiAic2lnIiwKICAgICAgICAia2lkIjogInB1a19mZF9zaWciLAogICAgICAgICJrdHkiOiAiRUMiLAogICAgICAgICJjcnYiOiAiUC0yNTYiLAogICAgICAgICJ4IjogIjliSnMyN1lBZmxNVVdLNW54dWlGNlhBRzBKYXp1dndSaTFFcEZLMFhLaWsiLAogICAgICAgICJ5IjogIlA4bHpOVlJPZ1R1d2JEcXNkOHJUMUFJM3plejk0SEJzVERwT3ZhalAwclkiLAogICAgICAgICJhbGciOiAiRVMyNTYiCiAgICAgIH0KICAgIF0KICB9LAogICJhdXRob3JpdHlfaGludHMiOiBbCiAgICAiaHR0cHM6Ly9hcHAtdGVzdC5mZWRlcmF0aW9ubWFzdGVyLmRlIgogIF0sCiAgIm1ldGFkYXRhIjogewogICAgIm9wZW5pZF9yZWx5aW5nX3BhcnR5IjogewogICAgICAic2lnbmVkX2p3a3NfdXJpIjogImh0dHA6Ly9sb2NhbGhvc3Q6ODA4NC9qd3MuanNvbiIsCiAgICAgICJvcmdhbml6YXRpb25fbmFtZSI6ICJGYWNoZGllbnN0MDA3IGRlcyBGZWRJZHAgUE9DcyIsCiAgICAgICJjbGllbnRfbmFtZSI6ICJGYWNoZGllbnN0MDA3IiwKICAgICAgImxvZ29fdXJpIjogImh0dHA6Ly9sb2NhbGhvc3Q6ODA4NC9ub0xvZ29ZZXQiLAogICAgICAicmVzcG9uc2VfdHlwZXMiOiBbCiAgICAgICAgImNvZGUiCiAgICAgIF0sCiAgICAgICJjbGllbnRfcmVnaXN0cmF0aW9uX3R5cGVzIjogWwogICAgICAgICJhdXRvbWF0aWMiCiAgICAgIF0sCiAgICAgICJncmFudF90eXBlcyI6IFsKICAgICAgICAiYXV0aG9yaXphdGlvbl9jb2RlIgogICAgICBdLAogICAgICAicmVxdWlyZV9wdXNoZWRfYXV0aG9yaXphdGlvbl9yZXF1ZXN0cyI6IHRydWUsCiAgICAgICJ0b2tlbl9lbmRwb2ludF9hdXRoX21ldGhvZCI6ICJzZWxmX3NpZ25lZF90bHNfY2xpZW50X2F1dGgiLAogICAgICAiZGVmYXVsdF9hY3JfdmFsdWVzIjogWwogICAgICAgICJnZW1hdGlrLWVoZWFsdGgtbG9hLWhpZ2giCiAgICAgIF0sCiAgICAgICJpZF90b2tlbl9zaWduZWRfcmVzcG9uc2VfYWxnIjogIkVTMjU2IiwKICAgICAgImlkX3Rva2VuX2VuY3J5cHRlZF9yZXNwb25zZV9hbGciOiAiRUNESC1FUyIsCiAgICAgICJpZF90b2tlbl9lbmNyeXB0ZWRfcmVzcG9uc2VfZW5jIjogIkEyNTZHQ00iLAogICAgICAic2NvcGUiOiAidXJuOnRlbGVtYXRpazpkaXNwbGF5X25hbWUgdXJuOnRlbGVtYXRpazp2ZXJzaWNoZXJ0ZXIgb3BlbmlkIgogICAgfSwKICAgICJmZWRlcmF0aW9uX2VudGl0eSI6IHsKICAgICAgIm5hbWUiOiAiRmFjaGRpZW5zdDAwNyIsCiAgICAgICJjb250YWN0cyI6IFsKICAgICAgICAiU3VwcG9ydEBGYWNoZGllbnN0MDA3LmRlIgogICAgICBdLAogICAgICAiaG9tZXBhZ2VfdXJpIjogImh0dHBzOi8vRmFjaGRpZW5zdDAwNy5kZSIKICAgIH0KICB9Cn0.XomqqjzmGfu3LFySjaKrfHcFStBK8lWW8uxH9HmNhdYoslBVd4z5t6I_DQQ2gbe5WWvKoGl0pVpGlGf5oIGR7Q";

  private static final String ENTITY_STMNT_MISSING_CLAIM_SCOPE =
      "eyJhbGciOiJFUzI1NiIsInR5cCI6ImVudGl0eS1zdGF0ZW1lbnQrand0Iiwia2lkIjoicHVrX2ZkX3NpZyJ9.ewogICJpc3MiOiAiaHR0cDovL2xvY2FsaG9zdDo4MDg0IiwKICAic3ViIjogImh0dHA6Ly9sb2NhbGhvc3Q6ODA4NCIsCiAgImlhdCI6IDE3MDIwNTA0NTEsCiAgImV4cCI6IDIzMzMyMDI0NTEsCiAgImp3a3MiOiB7CiAgICAia2V5cyI6IFsKICAgICAgewogICAgICAgICJ1c2UiOiAic2lnIiwKICAgICAgICAia2lkIjogInB1a19mZF9zaWciLAogICAgICAgICJrdHkiOiAiRUMiLAogICAgICAgICJjcnYiOiAiUC0yNTYiLAogICAgICAgICJ4IjogIjliSnMyN1lBZmxNVVdLNW54dWlGNlhBRzBKYXp1dndSaTFFcEZLMFhLaWsiLAogICAgICAgICJ5IjogIlA4bHpOVlJPZ1R1d2JEcXNkOHJUMUFJM3plejk0SEJzVERwT3ZhalAwclkiLAogICAgICAgICJhbGciOiAiRVMyNTYiCiAgICAgIH0KICAgIF0KICB9LAogICJhdXRob3JpdHlfaGludHMiOiBbCiAgICAiaHR0cHM6Ly9hcHAtdGVzdC5mZWRlcmF0aW9ubWFzdGVyLmRlIgogIF0sCiAgIm1ldGFkYXRhIjogewogICAgIm9wZW5pZF9yZWx5aW5nX3BhcnR5IjogewogICAgICAic2lnbmVkX2p3a3NfdXJpIjogImh0dHA6Ly9sb2NhbGhvc3Q6ODA4NC9qd3MuanNvbiIsCiAgICAgICJvcmdhbml6YXRpb25fbmFtZSI6ICJGYWNoZGllbnN0MDA3IGRlcyBGZWRJZHAgUE9DcyIsCiAgICAgICJjbGllbnRfbmFtZSI6ICJGYWNoZGllbnN0MDA3IiwKICAgICAgImxvZ29fdXJpIjogImh0dHA6Ly9sb2NhbGhvc3Q6ODA4NC9ub0xvZ29ZZXQiLAogICAgICAicmVkaXJlY3RfdXJpcyI6IFsKICAgICAgICAiaHR0cHM6Ly9GYWNoZGllbnN0MDA3LmRlL2NsaWVudCIsCiAgICAgICAgImh0dHBzOi8vcmVkaXJlY3QudGVzdHN1aXRlLmdzaSIsCiAgICAgICAgImh0dHBzOi8vaWRwZmFkaS5kZXYuZ2VtYXRpay5zb2x1dGlvbnMvYXV0aCIKICAgICAgXSwKICAgICAgInJlc3BvbnNlX3R5cGVzIjogWwogICAgICAgICJjb2RlIgogICAgICBdLAogICAgICAiY2xpZW50X3JlZ2lzdHJhdGlvbl90eXBlcyI6IFsKICAgICAgICAiYXV0b21hdGljIgogICAgICBdLAogICAgICAiZ3JhbnRfdHlwZXMiOiBbCiAgICAgICAgImF1dGhvcml6YXRpb25fY29kZSIKICAgICAgXSwKICAgICAgInJlcXVpcmVfcHVzaGVkX2F1dGhvcml6YXRpb25fcmVxdWVzdHMiOiB0cnVlLAogICAgICAidG9rZW5fZW5kcG9pbnRfYXV0aF9tZXRob2QiOiAic2VsZl9zaWduZWRfdGxzX2NsaWVudF9hdXRoIiwKICAgICAgImRlZmF1bHRfYWNyX3ZhbHVlcyI6IFsKICAgICAgICAiZ2VtYXRpay1laGVhbHRoLWxvYS1oaWdoIgogICAgICBdLAogICAgICAiaWRfdG9rZW5fc2lnbmVkX3Jlc3BvbnNlX2FsZyI6ICJFUzI1NiIsCiAgICAgICJpZF90b2tlbl9lbmNyeXB0ZWRfcmVzcG9uc2VfYWxnIjogIkVDREgtRVMiLAogICAgICAiaWRfdG9rZW5fZW5jcnlwdGVkX3Jlc3BvbnNlX2VuYyI6ICJBMjU2R0NNIgogICAgfSwKICAgICJmZWRlcmF0aW9uX2VudGl0eSI6IHsKICAgICAgIm5hbWUiOiAiRmFjaGRpZW5zdDAwNyIsCiAgICAgICJjb250YWN0cyI6IFsKICAgICAgICAiU3VwcG9ydEBGYWNoZGllbnN0MDA3LmRlIgogICAgICBdLAogICAgICAiaG9tZXBhZ2VfdXJpIjogImh0dHBzOi8vRmFjaGRpZW5zdDAwNy5kZSIKICAgIH0KICB9Cn0=.XomqqjzmGfu3LFySjaKrfHcFStBK8lWW8uxH9HmNhdYoslBVd4z5t6I_DQQ2gbe5WWvKoGl0pVpGlGf5oIGR7Q";

  @Test
  void test_getRedirectUrisEntityStatementRp_VALID() {
    assertDoesNotThrow(
        () -> EntityStatementRpReader.getRedirectUrisEntityStatementRp(VALID_ENTITY_STMNT));
    assertThat(EntityStatementRpReader.getRedirectUrisEntityStatementRp(VALID_ENTITY_STMNT))
        .isEqualTo(
            List.of(
                "https://Fachdienst007.de/client",
                "https://redirect.testsuite.gsi",
                "https://idpfadi.dev.gematik.solutions/auth"));
  }

  @Test
  void test_getRedirectUrisEntityStatementRp_throwsException_INVALID() {
    assertThatThrownBy(
            () ->
                EntityStatementRpReader.getRedirectUrisEntityStatementRp(
                    new JsonWebToken(ENTITY_STMNT_MISSING_CLAIM_REDIRECT_URIS)))
        .isInstanceOf(NullPointerException.class)
        .hasMessageContaining("missing claim: redirect_uris");
  }

  @Test
  void test_getScopesFromEntityStatementRp_VALID() {
    assertDoesNotThrow(
        () -> EntityStatementRpReader.getScopesFromEntityStatementRp(VALID_ENTITY_STMNT));
    assertThat(EntityStatementRpReader.getScopesFromEntityStatementRp(VALID_ENTITY_STMNT))
        .isEqualTo(List.of("urn:telematik:display_name", "urn:telematik:versicherter", "openid"));
  }

  @Test
  void test_getScopesFromEntityStatementRp_throwsException_INVALID() {
    assertThatThrownBy(
            () ->
                EntityStatementRpReader.getScopesFromEntityStatementRp(
                    new JsonWebToken(ENTITY_STMNT_MISSING_CLAIM_SCOPE)))
        .isInstanceOf(NullPointerException.class)
        .hasMessageContaining("missing claim: scope");
  }

  @Test
  void test_getRpTlsClientCerts_VALID() {
    try (final MockedStatic<HttpClient> mockedStatic = Mockito.mockStatic(HttpClient.class)) {
      mockedStatic
          .when(() -> HttpClient.fetchSignedJwks(any()))
          .thenReturn(Optional.of(new JsonWebToken(SIGNED_JWKS)));
      assertDoesNotThrow(() -> EntityStatementRpReader.getRpTlsClientCerts(VALID_ENTITY_STMNT));
      assertThat(EntityStatementRpReader.getRpTlsClientCerts(VALID_ENTITY_STMNT)).isNotNull();
    }
  }

  @Test
  void test_getRpTlsClientCerts_twoCerts_VALID() {
    try (final MockedStatic<HttpClient> mockedStatic = Mockito.mockStatic(HttpClient.class)) {
      mockedStatic
          .when(() -> HttpClient.fetchSignedJwks(any()))
          .thenReturn(Optional.of(new JsonWebToken(SIGNED_JWKS_TWO_CERTS)));
      assertDoesNotThrow(() -> EntityStatementRpReader.getRpTlsClientCerts(VALID_ENTITY_STMNT));
      final List<X509Certificate> certs =
          EntityStatementRpReader.getRpTlsClientCerts(VALID_ENTITY_STMNT);
      assertThat(certs).isNotNull();
      assertThat(certs).hasSize(2);
    }
  }

  @Test
  void test_getRpTlsClientCerts_fromEntityStatementRp_VALID() {
    assertDoesNotThrow(
        () ->
            EntityStatementRpReader.getRpTlsClientCerts(
                new JsonWebToken(ENTITY_STATEMENT_WITH_CERT)));
    assertThat(
            EntityStatementRpReader.getRpTlsClientCerts(
                new JsonWebToken(ENTITY_STATEMENT_WITH_CERT)))
        .isNotNull();
  }

  @Test
  void test_getRpTlsClientCerts_throwsException_INVALID() {
    try (final MockedStatic<HttpClient> mockedStatic = Mockito.mockStatic(HttpClient.class)) {
      mockedStatic
          .when(() -> HttpClient.fetchSignedJwks(any()))
          .thenReturn(Optional.of(new JsonWebToken(SIGNED_JWKS_WITHOUT_CERT)));
      assertThatThrownBy(() -> EntityStatementRpReader.getRpTlsClientCerts(VALID_ENTITY_STMNT))
          .isInstanceOf(GsiException.class)
          .hasMessageContaining("No TLS client certificate for relying party found");
    }
  }

  @Test
  void test_getRpEncKey_fromSignedJwks_VALID() {
    try (final MockedStatic<HttpClient> mockedStatic = Mockito.mockStatic(HttpClient.class)) {
      mockedStatic
          .when(() -> HttpClient.fetchSignedJwks(any()))
          .thenReturn(Optional.of(new JsonWebToken(SIGNED_JWKS)));
      assertDoesNotThrow(() -> EntityStatementRpReader.getRpEncKey(VALID_ENTITY_STMNT));
      assertThat(EntityStatementRpReader.getRpEncKey(VALID_ENTITY_STMNT)).isNotNull();
    }
  }

  @Test
  void test_getRpEncKey_fromEntityStatementRp_VALID() {
    assertDoesNotThrow(
        () ->
            EntityStatementRpReader.getRpEncKey(
                new JsonWebToken(ENTITY_STMNT_FACHDIENST_WITH_OPTIONAL_JWKS)));
    assertThat(
            EntityStatementRpReader.getRpEncKey(
                new JsonWebToken(ENTITY_STMNT_FACHDIENST_WITH_OPTIONAL_JWKS)))
        .isNotNull();
  }

  @Test
  void test_getRpEncKey_throwsException_INVALID() {
    try (final MockedStatic<HttpClient> mockedStatic = Mockito.mockStatic(HttpClient.class)) {
      mockedStatic
          .when(() -> HttpClient.fetchSignedJwks(any()))
          .thenReturn(Optional.of(new JsonWebToken(SIGNED_JWKS_WITHOUT_ENCKEY)));
      assertThatThrownBy(() -> EntityStatementRpReader.getRpEncKey(VALID_ENTITY_STMNT))
          .isInstanceOf(GsiException.class)
          .hasMessageContaining("Encryption key for relying party not found");
    }
  }
}
