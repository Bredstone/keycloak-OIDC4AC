/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.protocol.oidc4ac.delivery;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.Test;
import org.keycloak.protocol.oidc4ac.model.AuthenticationEvent;
import org.keycloak.protocol.oidc4ac.model.AuthenticationMethodExecution;
import org.keycloak.protocol.oidc4ac.request.AmrDetailsClaimRequest;
import org.keycloak.protocol.oidc4ac.request.AmrDetailsRequestParser;
import org.keycloak.util.JsonSerialization;

public class AmrDetailsProjectionTest {

    @Test
    @SuppressWarnings("unchecked")
    public void eachLocationCanReceiveAnIndependentProjectionOfOneSnapshot() throws Exception {
        AuthenticationEvent event = new AuthenticationEvent(List.of(new AuthenticationMethodExecution("pwd",
                Instant.parse("2026-07-25T12:00:00Z"), Map.of("issuer", text("local")),
                Optional.of(Map.of("pwd_derivation_algorithm", text("argon2id"), "pwd_iterations", text("210000"))))));
        AmrDetailsClaimRequest idTokenRequest = AmrDetailsRequestParser.parseClaimsParameter("""
                {"id_token":{"amr_details":{"amr_identifier":{"value":"pwd"},"amr_properties":
                {"pwd_derivation_algorithm":null}}}}
                """).idToken().orElseThrow();
        AmrDetailsClaimRequest userInfoRequest = AmrDetailsRequestParser.parseClaimsParameter("""
                {"userinfo":{"amr_details":{"amr_identifier":{"value":"pwd"},"amr_metadata":{"issuer":null}}}}
                """).userInfo().orElseThrow();

        Map<String, Object> idTokenDetail = AmrDetailsProjection.project(idTokenRequest, event).get(0);
        Map<String, Object> userInfoDetail = AmrDetailsProjection.project(userInfoRequest, event).get(0);

        assertEquals("pwd", idTokenDetail.get("amr_identifier"));
        assertEquals("2026-07-25T12:00:00Z", ((Map<String, Object>) idTokenDetail.get("amr_metadata")).get("time"));
        assertEquals("argon2id", ((Map<String, Object>) idTokenDetail.get("amr_properties")).get("pwd_derivation_algorithm"));
        assertFalse(((Map<String, Object>) idTokenDetail.get("amr_properties")).containsKey("pwd_iterations"));
        assertEquals("local", ((Map<String, Object>) userInfoDetail.get("amr_metadata")).get("issuer"));
        assertFalse(userInfoDetail.containsKey("amr_properties"));
    }

    @Test
    @SuppressWarnings("unchecked")
    public void expressionCannotRemoveOtherExecutionsFromTheAuthenticationEvent() throws Exception {
        AuthenticationEvent event = new AuthenticationEvent(List.of(
                new AuthenticationMethodExecution("pwd", Instant.parse("2026-07-25T12:00:00Z"),
                        Map.of("issuer", text("local")), Optional.of(Map.of("pwd_iterations", text("210000")))),
                new AuthenticationMethodExecution("face", Instant.parse("2026-07-25T12:01:00Z"),
                        Map.of("issuer", text("remote")), Optional.of(Map.of("liveness_check", text("passed"))))));
        AmrDetailsClaimRequest request = AmrDetailsRequestParser.parseClaimsParameter("""
                {"id_token":{"amr_details":{"amr_identifier":{"value":"face"},"amr_metadata":
                {"issuer":null},"amr_properties":{"liveness_check":null}}}}
                """).idToken().orElseThrow();

        List<Map<String, Object>> details = AmrDetailsProjection.project(request, event);

        assertEquals(2, details.size());
        Map<String, Object> password = details.get(0);
        Map<String, Object> face = details.get(1);
        assertEquals("pwd", password.get("amr_identifier"));
        assertEquals("2026-07-25T12:00:00Z", ((Map<String, Object>) password.get("amr_metadata")).get("time"));
        assertEquals(1, ((Map<String, Object>) password.get("amr_metadata")).size());
        assertFalse(password.containsKey("amr_properties"));
        assertEquals("face", face.get("amr_identifier"));
        assertEquals("2026-07-25T12:01:00Z", ((Map<String, Object>) face.get("amr_metadata")).get("time"));
        assertEquals("remote", ((Map<String, Object>) face.get("amr_metadata")).get("issuer"));
        assertEquals("passed", ((Map<String, Object>) face.get("amr_properties")).get("liveness_check"));
    }

    @Test
    @SuppressWarnings("unchecked")
    public void anUnconstrainedRequestReceivesTheCompleteEvent() throws Exception {
        AuthenticationEvent event = new AuthenticationEvent(List.of(new AuthenticationMethodExecution("otp",
                Instant.parse("2026-07-25T12:00:00Z"), Map.of(), Optional.empty())));
        AmrDetailsClaimRequest request = AmrDetailsRequestParser.parseClaimsParameter(
                "{\"id_token\":{\"amr_details\":null}}").idToken().orElseThrow();

        Map<String, Object> detail = AmrDetailsProjection.project(request, event).get(0);
        assertEquals("otp", detail.get("amr_identifier"));
        assertTrue(((Map<String, Object>) detail.get("amr_metadata")).containsKey("time"));
    }

    private static com.fasterxml.jackson.databind.JsonNode text(String value) {
        return JsonSerialization.mapper.valueToTree(value);
    }
}
