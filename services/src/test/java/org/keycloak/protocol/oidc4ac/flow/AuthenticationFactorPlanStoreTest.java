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

import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.keycloak.sessions.AuthenticationSessionModel;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class AuthenticationFactorPlanStoreTest {

    @Test
    public void firstPlanWinsForTheAuthenticationSessionAndOnlyMatchesItsContainer() {
        Map<String, String> notes = new HashMap<>();
        AuthenticationSessionModel session = session(notes);

        AuthenticationFactorPlan first = plan("factor-container", "pwd", "otp");
        AuthenticationFactorPlan second = plan("another-container", "email");

        assertEquals(first, AuthenticationFactorPlanStore.storeIfAbsent(session, first));
        assertEquals(first, AuthenticationFactorPlanStore.storeIfAbsent(session, second));
        assertEquals(first, AuthenticationFactorPlanStore.forFlow(session, "factor-container").orElseThrow());
        assertTrue(AuthenticationFactorPlanStore.forFlow(session, "another-container").isEmpty());
        assertFalse(notes.isEmpty());
    }

    @Test
    public void progressMovesOnlyToTheNextPreplannedBranch() {
        Map<String, String> notes = new HashMap<>();
        AuthenticationSessionModel session = session(notes);
        AuthenticationFactorPlan plan = new AuthenticationFactorPlan("factor-container", List.of(new AuthenticationFactorPlanStep(List.of(
                new AuthenticationFactorPlanBranch(List.of("pop")),
                new AuthenticationFactorPlanBranch(List.of("email"))))));

        AuthenticationFactorPlanStore.storeIfAbsent(session, plan);
        AuthenticationFactorPlanStore.setCurrentExecution(session, plan, 0, 0, "pop");

        assertEquals(0, AuthenticationFactorPlanStore.activeBranch(session, plan, 0));
        assertTrue(AuthenticationFactorPlanStore.advanceBranch(session, plan, 0));
        assertEquals(1, AuthenticationFactorPlanStore.activeBranch(session, plan, 0));
        assertFalse(AuthenticationFactorPlanStore.advanceBranch(session, plan, 0));
    }

    @Test
    public void setupRequiredExecutionIsRequestScopedAndCanBeCleared() {
        Map<String, String> notes = new HashMap<>();
        AuthenticationSessionModel session = session(notes);

        AuthenticationFactorPlanStore.markSetupRequired(session, "otp-execution");
        assertEquals("otp-execution", AuthenticationFactorPlanStore.pendingSetupExecution(session).orElseThrow());

        AuthenticationFactorPlanStore.clearSetupRequired(session);
        assertTrue(AuthenticationFactorPlanStore.pendingSetupExecution(session).isEmpty());
    }

    private static AuthenticationFactorPlan plan(String flowId, String... executions) {
        return new AuthenticationFactorPlan(flowId, List.of(new AuthenticationFactorPlanStep(List.of(
                new AuthenticationFactorPlanBranch(List.of(executions))))));
    }

    @SuppressWarnings("unchecked")
    private static AuthenticationSessionModel session(Map<String, String> notes) {
        return (AuthenticationSessionModel) Proxy.newProxyInstance(AuthenticationSessionModel.class.getClassLoader(),
                new Class<?>[] { AuthenticationSessionModel.class }, (proxy, method, arguments) -> {
                    if ("getAuthNote".equals(method.getName())) {
                        return notes.get(arguments[0]);
                    }
                    if ("setAuthNote".equals(method.getName())) {
                        notes.put((String) arguments[0], (String) arguments[1]);
                        return null;
                    }
                    if ("removeAuthNote".equals(method.getName())) {
                        notes.remove(arguments[0]);
                        return null;
                    }
                    if ("toString".equals(method.getName())) {
                        return "AuthenticationSessionModel";
                    }
                    throw new UnsupportedOperationException(method.getName());
                });
    }
}
