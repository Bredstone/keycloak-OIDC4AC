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

import java.io.IOException;
import java.util.Optional;

import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;

/** Keeps one immutable dynamic-factor plan in the server-side authentication session. */
public final class AuthenticationFactorPlanStore {

    public static final String AUTH_SESSION_FACTOR_PLAN_NOTE = "oidc4ac.authentication-factor-plan";

    private AuthenticationFactorPlanStore() {
    }

    public static Optional<AuthenticationFactorPlan> forFlow(AuthenticationSessionModel authenticationSession, String flowId) {
        return read(authenticationSession).filter(plan -> plan.factorFlowId().equals(flowId));
    }

    public static Optional<AuthenticationFactorPlan> read(AuthenticationSessionModel authenticationSession) {
        String serialized = authenticationSession.getAuthNote(AUTH_SESSION_FACTOR_PLAN_NOTE);
        if (serialized == null || serialized.isBlank()) {
            return Optional.empty();
        }
        try {
            return Optional.of(JsonSerialization.readValue(serialized, AuthenticationFactorPlan.class));
        } catch (IOException | RuntimeException e) {
            return Optional.empty();
        }
    }

    /** The first successful planner invocation fixes the route for this authorization. */
    public static AuthenticationFactorPlan storeIfAbsent(AuthenticationSessionModel authenticationSession,
            AuthenticationFactorPlan plan) {
        Optional<AuthenticationFactorPlan> existing = read(authenticationSession);
        if (existing.isPresent()) {
            return existing.orElseThrow();
        }
        try {
            authenticationSession.setAuthNote(AUTH_SESSION_FACTOR_PLAN_NOTE, JsonSerialization.writeValueAsString(plan));
            return plan;
        } catch (IOException e) {
            throw new IllegalStateException("Could not store OIDC4AC authentication factor plan", e);
        }
    }
}
