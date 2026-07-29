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
package org.keycloak.protocol.oidc4ac;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.Optional;

import org.junit.Test;
import org.keycloak.protocol.oidc4ac.evaluation.AmrDetailsRequirementsEvaluator;
import org.keycloak.protocol.oidc4ac.evaluation.AuthenticationRequirementsPlanner;
import org.keycloak.protocol.oidc4ac.model.AuthenticationEvent;
import org.keycloak.protocol.oidc4ac.model.AuthenticationMethodExecution;
import org.keycloak.protocol.oidc4ac.request.AllOfExpression;
import org.keycloak.protocol.oidc4ac.request.AmrDetailsClaimRequest;
import org.keycloak.protocol.oidc4ac.request.AmrDetailsClaimsRequest;
import org.keycloak.protocol.oidc4ac.request.AmrDetailsRequestException;
import org.keycloak.protocol.oidc4ac.request.AmrDetailsRequestParser;
import org.keycloak.protocol.oidc4ac.request.OneOfExpression;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;

public class AmrDetailsRequestParserTest {

    private static final Instant NOW = Instant.parse("2026-07-25T12:00:00Z");

    @Test
    public void parsesClaimLevelEssentialAndNestedExpressions() throws Exception {
        AmrDetailsClaimsRequest request = AmrDetailsRequestParser.parseClaimsParameter("""
                {
                  "id_token": {
                    "amr_details": {
                      "essential": true,
                      "one_of": [
                        {"all_of": [
                          {"amr_identifier": {"value": "pwd"}, "amr_metadata": {"time": null}},
                          {"amr_identifier": {"value": "otp"}, "amr_metadata": {"time": null}, "amr_properties": {
                            "otp_algorithm": {"essential": true, "values": ["TOTP", "HOTP"]}
                          }}
                        ]},
                        {"amr_identifier": {"value": "pop"}, "amr_metadata": {"time": null}}
                      ]
                    }
                  },
                  "userinfo": {"amr_details": null}
                }
                """);

        assertTrue(request.idToken().orElseThrow().essential());
        assertTrue(request.idToken().orElseThrow().expression().orElseThrow() instanceof OneOfExpression);
        assertTrue(request.userInfo().isPresent());
        assertFalse(request.userInfo().orElseThrow().essential());
        assertTrue(request.userInfo().orElseThrow().expression().isEmpty());
    }

    @Test
    public void rejectsInvalidGrammar() {
        assertInvalid("{\"id_token\":{\"amr_details\":{\"all_of\":[]}}}");
        assertInvalid("{\"id_token\":{\"amr_details\":{\"one_of\":[{\"essential\":true,\"amr_identifier\":{\"value\":\"pwd\"}}]}}}");
        assertInvalid("{\"id_token\":{\"amr_details\":{\"amr_identifier\":{\"value\":\"pwd\",\"values\":[\"otp\"]}}}}");
        assertInvalid("{\"id_token\":{\"amr_details\":{\"amr_identifier\":{\"value\":\"pwd\"},\"amr_properties\":{\"x\":{\"value\":1,\"values\":[2]}}}}}");
        assertInvalid("{\"id_token\":{\"amr_details\":{\"amr_identifier\":{\"value\":\"pwd\"},\"amr_metadata\":{\"iss\":{\"max_age\":10}}}}}");
        assertInvalid("{\"id_token\":{\"amr_details\":{\"amr_metadata\":{}}}}");
    }

    @Test
    public void evaluatesOneOfWithoutBranchCommitmentAndDoesNotExcludeExtraMethods() throws Exception {
        AmrDetailsClaimRequest request = AmrDetailsRequestParser.parseClaimsParameter("""
                {"id_token":{"amr_details":{"essential":true,"one_of":[
                  {"amr_identifier":{"value":"face"},"amr_metadata":{"time":null},"amr_properties":{"liveness_check":{"essential":true,"value":true}}},
                  {"amr_identifier":{"value":"otp"},"amr_metadata":{"time":null}}
                ]}}}
                """).idToken().orElseThrow();

        AuthenticationEvent event = new AuthenticationEvent(java.util.List.of(
                execution("pwd", NOW.minusSeconds(10), Map.of(), Optional.empty()),
                execution("otp", NOW.minusSeconds(5), Map.of(), Optional.of(Map.of("otp_algorithm", text("TOTP"))))));

        AmrDetailsRequirementsEvaluator evaluator = new AmrDetailsRequirementsEvaluator(Clock.fixed(NOW, ZoneOffset.UTC));
        assertTrue(evaluator.evaluate(request, Optional.of(event)).satisfies(request.essential(), true));
    }

    @Test
    public void evaluatesLocallyEssentialPropertiesAndFreshness() throws Exception {
        AmrDetailsClaimRequest missingProperty = AmrDetailsRequestParser.parseClaimsParameter("""
                {"id_token":{"amr_details":{"essential":true,"amr_identifier":{"value":"otp"},"amr_metadata":{"time":null},
                "amr_properties":{"otp_algorithm":{"essential":true,"value":"TOTP"}}}}}
                """).idToken().orElseThrow();
        AmrDetailsClaimRequest stalePassword = AmrDetailsRequestParser.parseClaimsParameter("""
                {"id_token":{"amr_details":{"essential":true,"amr_identifier":{"value":"pwd"},
                "amr_metadata":{"time":{"essential":true,"max_age":300}}}}}
                """).idToken().orElseThrow();

        AuthenticationEvent event = new AuthenticationEvent(java.util.List.of(
                execution("otp", NOW.minusSeconds(10), Map.of(), Optional.empty()),
                execution("pwd", NOW.minusSeconds(301), Map.of(), Optional.empty())));
        AmrDetailsRequirementsEvaluator evaluator = new AmrDetailsRequirementsEvaluator(Clock.fixed(NOW, ZoneOffset.UTC));

        assertFalse(evaluator.evaluate(missingProperty, Optional.of(event)).satisfies(true, true));
        assertFalse(evaluator.evaluate(stalePassword, Optional.of(event)).satisfies(true, true));
    }

    @Test
    public void acceptsMaxAgeZeroForAnExecutionInTheCurrentSecond() throws Exception {
        AmrDetailsClaimRequest request = AmrDetailsRequestParser.parseClaimsParameter("""
                {"id_token":{"amr_details":{"essential":true,"amr_identifier":{"value":"pwd"},
                "amr_metadata":{"time":{"essential":true,"max_age":0}}}}}
        """).idToken().orElseThrow();
        AuthenticationEvent event = new AuthenticationEvent(java.util.List.of(
                execution("pwd", NOW.plusMillis(250), Map.of(), Optional.empty())));

        AmrDetailsRequirementsEvaluator evaluator = new AmrDetailsRequirementsEvaluator(
                Clock.fixed(NOW.plusMillis(500), ZoneOffset.UTC));
        assertTrue(evaluator.evaluate(request, Optional.of(event)).satisfies(true, true));
    }

    @Test
    public void combinesEssentialDeliveryLocationsForOneEvent() throws Exception {
        AmrDetailsClaimsRequest requests = AmrDetailsRequestParser.parseClaimsParameter("""
                {
                  "id_token":{"amr_details":{"essential":true,"amr_identifier":{"value":"pwd"},"amr_metadata":{"time":null}}},
                  "userinfo":{"amr_details":{"essential":true,"amr_identifier":{"value":"otp"},"amr_metadata":{"time":null}}}
                }
                """);
        AuthenticationEvent passwordOnly = new AuthenticationEvent(java.util.List.of(execution("pwd", NOW, Map.of(), Optional.empty())));
        AuthenticationEvent passwordAndOtp = new AuthenticationEvent(java.util.List.of(
                execution("pwd", NOW, Map.of(), Optional.empty()), execution("otp", NOW, Map.of(), Optional.empty())));
        AmrDetailsRequirementsEvaluator evaluator = new AmrDetailsRequirementsEvaluator(Clock.fixed(NOW, ZoneOffset.UTC));

        assertFalse(evaluator.essentialRequirementsSatisfied(requests, Optional.of(passwordOnly)));
        assertTrue(evaluator.essentialRequirementsSatisfied(requests, Optional.of(passwordAndOtp)));
    }

    @Test
    public void treatsNonEssentialConstraintsAsBestEffort() throws Exception {
        AmrDetailsClaimRequest request = AmrDetailsRequestParser.parseClaimsParameter("""
                {"id_token":{"amr_details":{"essential":true,"amr_identifier":{"value":"otp"},"amr_metadata":{"time":null},
                "amr_properties":{"otp_algorithm":{"value":"TOTP"}}}}}
                """).idToken().orElseThrow();
        AuthenticationEvent event = new AuthenticationEvent(java.util.List.of(
                execution("otp", NOW, Map.of(), Optional.of(Map.of("otp_algorithm", text("HOTP"))))));

        AmrDetailsRequirementsEvaluator evaluator = new AmrDetailsRequirementsEvaluator(Clock.fixed(NOW, ZoneOffset.UTC));
        assertTrue(evaluator.evaluate(request, Optional.of(event)).satisfies(true, true));
    }

    @Test
    public void plannerRetriesConfiguredBrowserFlowForUnmetEssentialOrPreference() throws Exception {
        AuthenticationRequirementsPlanner planner = new AuthenticationRequirementsPlanner(Clock.fixed(NOW, ZoneOffset.UTC));
        AuthenticationEvent passwordOnly = new AuthenticationEvent(java.util.List.of(
                execution("pwd", NOW.minusSeconds(10), Map.of(), Optional.empty())));
        AmrDetailsClaimsRequest essentialOtp = AmrDetailsRequestParser.parseClaimsParameter("""
                {"id_token":{"amr_details":{"essential":true,"amr_identifier":{"value":"otp"},"amr_metadata":{"time":null}}}}
                """);
        AmrDetailsClaimsRequest preferredOtp = AmrDetailsRequestParser.parseClaimsParameter("""
                {"id_token":{"amr_details":{"amr_identifier":{"value":"otp"},"amr_metadata":{"time":null}}}}
                """);
        AmrDetailsClaimsRequest satisfied = AmrDetailsRequestParser.parseClaimsParameter("""
                {"id_token":{"amr_details":{"essential":true,"amr_identifier":{"value":"pwd"},"amr_metadata":{"time":null}}}}
                """);

        assertTrue(planner.shouldForceBrowserReauthentication(essentialOtp, Optional.of(passwordOnly)));
        assertTrue(planner.shouldForceBrowserReauthentication(preferredOtp, Optional.of(passwordOnly)));
        assertFalse(planner.shouldForceBrowserReauthentication(satisfied, Optional.of(passwordOnly)));
    }

    private static AuthenticationMethodExecution execution(String identifier, Instant time,
            Map<String, com.fasterxml.jackson.databind.JsonNode> metadata,
            Optional<Map<String, com.fasterxml.jackson.databind.JsonNode>> properties) {
        return new AuthenticationMethodExecution(identifier, time, metadata, properties);
    }

    private static com.fasterxml.jackson.databind.JsonNode text(String value) {
        return JsonNodeFactory.instance.textNode(value);
    }

    private static void assertInvalid(String claims) {
        assertThrows(AmrDetailsRequestException.class, () -> AmrDetailsRequestParser.parseClaimsParameter(claims));
    }
}
