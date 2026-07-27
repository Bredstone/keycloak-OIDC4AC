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
    public static final String AUTH_SESSION_FACTOR_PLAN_PROGRESS_NOTE = "oidc4ac.authentication-factor-plan-progress";
    public static final String AUTH_SESSION_FACTOR_SETUP_NOTE = "oidc4ac.authentication-factor-setup";

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

    public static int activeBranch(AuthenticationSessionModel authenticationSession, AuthenticationFactorPlan plan, int stepIndex) {
        return readProgress(authenticationSession).filter(progress -> progress.factorFlowId().equals(plan.factorFlowId())
                && progress.stepIndex() == stepIndex).map(AuthenticationFactorPlanProgress::branchIndex).orElse(0);
    }

    public static void setCurrentExecution(AuthenticationSessionModel authenticationSession, AuthenticationFactorPlan plan,
            int stepIndex, int branchIndex, String executionId) {
        writeProgress(authenticationSession, new AuthenticationFactorPlanProgress(plan.factorFlowId(), stepIndex, branchIndex, executionId));
    }

    public static boolean advanceBranch(AuthenticationSessionModel authenticationSession, AuthenticationFactorPlan plan, int stepIndex) {
        int nextBranch = activeBranch(authenticationSession, plan, stepIndex) + 1;
        if (nextBranch >= plan.steps().get(stepIndex).branches().size()) {
            return false;
        }
        writeProgress(authenticationSession, new AuthenticationFactorPlanProgress(plan.factorFlowId(), stepIndex, nextBranch, null));
        return true;
    }

    public static Optional<AuthenticationFactorPlanProgress> progress(AuthenticationSessionModel authenticationSession,
            AuthenticationFactorPlan plan) {
        return readProgress(authenticationSession).filter(progress -> progress.factorFlowId().equals(plan.factorFlowId()));
    }

    public static void clearProgress(AuthenticationSessionModel authenticationSession) {
        authenticationSession.removeAuthNote(AUTH_SESSION_FACTOR_PLAN_PROGRESS_NOTE);
    }

    public static void markSetupRequired(AuthenticationSessionModel authenticationSession, String executionId) {
        authenticationSession.setAuthNote(AUTH_SESSION_FACTOR_SETUP_NOTE, executionId);
    }

    public static Optional<String> pendingSetupExecution(AuthenticationSessionModel authenticationSession) {
        return Optional.ofNullable(authenticationSession.getAuthNote(AUTH_SESSION_FACTOR_SETUP_NOTE))
                .filter(value -> !value.isBlank());
    }

    public static void clearSetupRequired(AuthenticationSessionModel authenticationSession) {
        authenticationSession.removeAuthNote(AUTH_SESSION_FACTOR_SETUP_NOTE);
    }

    private static Optional<AuthenticationFactorPlanProgress> readProgress(AuthenticationSessionModel authenticationSession) {
        String serialized = authenticationSession.getAuthNote(AUTH_SESSION_FACTOR_PLAN_PROGRESS_NOTE);
        if (serialized == null || serialized.isBlank()) {
            return Optional.empty();
        }
        try {
            return Optional.of(JsonSerialization.readValue(serialized, AuthenticationFactorPlanProgress.class));
        } catch (IOException | RuntimeException e) {
            return Optional.empty();
        }
    }

    private static void writeProgress(AuthenticationSessionModel authenticationSession, AuthenticationFactorPlanProgress progress) {
        try {
            authenticationSession.setAuthNote(AUTH_SESSION_FACTOR_PLAN_PROGRESS_NOTE, JsonSerialization.writeValueAsString(progress));
        } catch (IOException e) {
            throw new IllegalStateException("Could not store OIDC4AC authentication factor plan progress", e);
        }
    }
}
