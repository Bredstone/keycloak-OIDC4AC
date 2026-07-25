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
package org.keycloak.protocol.oidc4ac.flow;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.List;
import java.util.Set;

import org.junit.Test;
import org.keycloak.protocol.oidc4ac.request.AmrDetailsRequestParser;

public class AuthenticationFactorPlanPlannerTest {

    private final AuthenticationFactorPlanPlanner planner = new AuthenticationFactorPlanPlanner();

    @Test
    public void selectsAnArbitraryAllOfSetButUsesRealmPriorityRatherThanRequestOrder() throws Exception {
        AuthenticationFactorPlanResult result = planner.plan(request("""
                {"id_token":{"amr_details":{"essential":true,"all_of":[
                  {"amr_identifier":{"value":"otp"}},
                  {"amr_identifier":{"value":"email"}},
                  {"amr_identifier":{"value":"pwd"}},
                  {"amr_identifier":{"value":"pop"}}
                ]}}}
                """), "factors", List.of(
                binding("email-flow", "email", 40),
                binding("otp-flow", "otp", 30),
                binding("pop-flow", "pop", 20),
                binding("pwd-flow", "pwd", 10)));

        assertFalse(result.essentialRequirementsUnplannable());
        assertEquals(List.of("pwd-flow", "pop-flow", "otp-flow", "email-flow"), result.plan().executionIds());
    }

    @Test
    public void choosesOneOfBranchByRealmPolicyAndThenAppliesAllOf() throws Exception {
        AuthenticationFactorPlanResult result = planner.plan(request("""
                {"id_token":{"amr_details":{"essential":true,"all_of":[
                  {"amr_identifier":{"value":"pwd"}},
                  {"one_of":[
                    {"all_of":[
                      {"amr_identifier":{"value":"otp"}},
                      {"amr_identifier":{"value":"email"}}
                    ]},
                    {"amr_identifier":{"value":"pop"}}
                  ]}
                ]}}}
                """), "factors", List.of(
                binding("pwd-flow", "pwd", 10),
                binding("pop-flow", "pop", 20),
                binding("otp-flow", "otp", 30),
                binding("email-flow", "email", 40)));

        assertFalse(result.essentialRequirementsUnplannable());
        assertEquals(List.of("pwd-flow", "pop-flow"), result.plan().executionIds());
    }

    @Test
    public void refusesEssentialPropertyRequirementsWithoutACapableBinding() throws Exception {
        AuthenticationFactorPlanResult result = planner.plan(request("""
                {"id_token":{"amr_details":{"essential":true,"amr_identifier":{"value":"pwd"},
                  "amr_properties":{"pwd_iterations":{"essential":true}}}}}
                """), "factors", List.of(binding("pwd-flow", "pwd", 10)));

        assertTrue(result.essentialRequirementsUnplannable());
        assertTrue(result.plan().executionIds().isEmpty());
    }

    @Test
    public void optionalUnsupportedMethodDoesNotPreventTheConfiguredContainerFromCompleting() throws Exception {
        AuthenticationFactorPlanResult result = planner.plan(request("""
                {"userinfo":{"amr_details":{"essential":false,"amr_identifier":{"value":"email"}}}}
                """), "factors", List.of(binding("pwd-flow", "pwd", 10)));

        assertFalse(result.essentialRequirementsUnplannable());
        assertTrue(result.plan().executionIds().isEmpty());
    }

    private static AuthenticationFactorBinding binding(String executionId, String identifier, int priority) {
        return new AuthenticationFactorBinding(executionId, identifier, priority, Set.of());
    }

    private static org.keycloak.protocol.oidc4ac.request.AmrDetailsClaimsRequest request(String claims) throws Exception {
        return AmrDetailsRequestParser.parseClaimsParameter(claims);
    }
}
