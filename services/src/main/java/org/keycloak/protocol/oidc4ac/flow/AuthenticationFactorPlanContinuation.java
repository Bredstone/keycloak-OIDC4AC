/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package org.keycloak.protocol.oidc4ac.flow;

import java.util.Optional;

import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.RealmModel;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * Resumes a request-scoped factor plan after a required action provisions a
 * credential. Provisioning is not an authentication execution, so the plan
 * must be run again and record a fresh verification before authorization can
 * complete.
 */
public final class AuthenticationFactorPlanContinuation {

    private AuthenticationFactorPlanContinuation() {
    }

    public static boolean isPending(AuthenticationSessionModel authenticationSession) {
        return AuthenticationFactorPlanStore.pendingSetupExecution(authenticationSession).isPresent();
    }

    public static void prepareForResume(RealmModel realm, AuthenticationSessionModel authenticationSession) {
        Optional<String> pendingExecution = AuthenticationFactorPlanStore.pendingSetupExecution(authenticationSession);
        AuthenticationFactorPlanStore.clearSetupRequired(authenticationSession);
        if (pendingExecution.isEmpty()) {
            return;
        }

        AuthenticationExecutionModel current = realm.getAuthenticationExecutionById(pendingExecution.orElseThrow());
        if (current == null) {
            AuthenticationFactorPlanStore.clearProgress(authenticationSession);
            return;
        }

        // SETUP_REQUIRED is a processed status in Keycloak's normal flow. Mark
        // the planned execution and all containing flow executions as pending
        // again, while retaining successful preceding factors such as pwd.
        while (current != null) {
            authenticationSession.setExecutionStatus(current.getId(), AuthenticationSessionModel.ExecutionStatus.CHALLENGED);
            if (current.getParentFlow() == null) {
                break;
            }
            current = realm.getAuthenticationExecutionByFlowId(current.getParentFlow());
        }

        Optional<AuthenticationFactorPlan> plan = AuthenticationFactorPlanStore.read(authenticationSession);
        if (plan.isPresent()) {
            AuthenticationFactorPlanStore.progress(authenticationSession, plan.orElseThrow()).ifPresent(progress ->
                    AuthenticationFactorPlanStore.setCurrentExecution(authenticationSession, plan.orElseThrow(),
                            progress.stepIndex(), progress.branchIndex(), null));
        }
        authenticationSession.removeAuthNote(AuthenticationProcessor.CURRENT_AUTHENTICATION_EXECUTION);
    }
}
