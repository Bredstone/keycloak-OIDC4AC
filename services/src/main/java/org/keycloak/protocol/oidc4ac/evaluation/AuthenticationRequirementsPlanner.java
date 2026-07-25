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
package org.keycloak.protocol.oidc4ac.evaluation;

import java.time.Clock;
import java.util.Optional;

import org.keycloak.protocol.oidc4ac.model.AuthenticationEvent;
import org.keycloak.protocol.oidc4ac.request.AmrDetailsClaimRequest;
import org.keycloak.protocol.oidc4ac.request.AmrDetailsClaimsRequest;

/**
 * Selects the Keycloak browser-flow policy for an existing SSO Authentication
 * Event. It never selects a method or changes an authentication flow; a
 * reauthentication runs the realm's configured browser flow.
 */
public final class AuthenticationRequirementsPlanner {

    private final AmrDetailsRequirementsEvaluator evaluator;

    public AuthenticationRequirementsPlanner(Clock clock) {
        evaluator = new AmrDetailsRequirementsEvaluator(clock);
    }

    /**
     * Keycloak's experimental policy is to retry its configured browser flow
     * when an SSO event cannot satisfy an essential request or a requested
     * best-effort preference. The later evaluator remains authoritative: a
     * retried flow can only report what actually happened.
     */
    public boolean shouldForceBrowserReauthentication(AmrDetailsClaimsRequest requests, Optional<AuthenticationEvent> ssoEvent) {
        if (!evaluator.essentialRequirementsSatisfied(requests, ssoEvent)) {
            return true;
        }
        return requests.idToken().stream().anyMatch(request -> preferenceNeedsRetry(request, ssoEvent))
                || requests.userInfo().stream().anyMatch(request -> preferenceNeedsRetry(request, ssoEvent));
    }

    private boolean preferenceNeedsRetry(AmrDetailsClaimRequest request, Optional<AuthenticationEvent> ssoEvent) {
        return request.expression().map(expression -> ssoEvent.map(event -> !evaluator.matchesAllConstraints(expression, event)).orElse(true))
                .orElse(false);
    }
}
