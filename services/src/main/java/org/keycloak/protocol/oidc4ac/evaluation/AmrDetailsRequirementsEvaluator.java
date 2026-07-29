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

import java.math.BigDecimal;
import java.time.Clock;
import java.time.Instant;
import java.util.Optional;

import org.keycloak.protocol.oidc4ac.model.AuthenticationEvent;
import org.keycloak.protocol.oidc4ac.model.AuthenticationMethodExecution;
import org.keycloak.protocol.oidc4ac.request.AllOfExpression;
import org.keycloak.protocol.oidc4ac.request.AmrDetailsClaimRequest;
import org.keycloak.protocol.oidc4ac.request.AmrDetailsClaimsRequest;
import org.keycloak.protocol.oidc4ac.request.AuthenticationMethodExpression;
import org.keycloak.protocol.oidc4ac.request.MethodExpression;
import org.keycloak.protocol.oidc4ac.request.OneOfExpression;
import org.keycloak.protocol.oidc4ac.request.ValueConstraint;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * Evaluates the author-approved recursive Boolean request language against an
 * immutable Authentication Event. It does not plan or perform authentication.
 */
public final class AmrDetailsRequirementsEvaluator {

    private final Clock clock;

    public AmrDetailsRequirementsEvaluator(Clock clock) {
        this.clock = clock;
    }

    public AmrDetailsEvaluationResult evaluate(AmrDetailsClaimRequest request, Optional<AuthenticationEvent> event) {
        boolean claimAvailable = event.filter(value -> !value.executions().isEmpty()).isPresent();
        boolean expressionSatisfied = request.expression().map(expression -> event.map(value -> matches(expression, value)).orElse(false)).orElse(true);
        return new AmrDetailsEvaluationResult(claimAvailable, expressionSatisfied);
    }

    /** All essential ID Token and UserInfo requests must hold for the same event. */
    public boolean essentialRequirementsSatisfied(AmrDetailsClaimsRequest requests, Optional<AuthenticationEvent> event) {
        return requests.idToken().stream().allMatch(request -> {
            AmrDetailsEvaluationResult result = evaluate(request, event);
            return result.satisfies(request.essential(), request.expression().isPresent());
        }) && requests.userInfo().stream().allMatch(request -> {
            AmrDetailsEvaluationResult result = evaluate(request, event);
            return result.satisfies(request.essential(), request.expression().isPresent());
        });
    }

    public boolean matches(AuthenticationMethodExpression expression, AuthenticationEvent event) {
        return matches(expression, event, true);
    }

    /** Evaluates every requested constraint as a best-effort planning preference. */
    public boolean matchesAllConstraints(AuthenticationMethodExpression expression, AuthenticationEvent event) {
        return matches(expression, event, false);
    }

    private boolean matches(AuthenticationMethodExpression expression, AuthenticationEvent event, boolean essentialOnly) {
        if (expression instanceof AllOfExpression allOf) {
            return allOf.children().stream().allMatch(child -> matches(child, event, essentialOnly));
        }
        if (expression instanceof OneOfExpression oneOf) {
            return oneOf.children().stream().anyMatch(child -> matches(child, event, essentialOnly));
        }
        return matchesMethod((MethodExpression) expression, event, essentialOnly);
    }

    private boolean matchesMethod(MethodExpression expression, AuthenticationEvent event, boolean essentialOnly) {
        return event.executions().stream().anyMatch(execution -> expression.identifier().matches(execution.amrIdentifier())
                && matchesMetadata(expression, execution, essentialOnly) && matchesProperties(expression, execution, essentialOnly));
    }

    private boolean matchesMetadata(MethodExpression expression, AuthenticationMethodExecution execution, boolean essentialOnly) {
        return expression.metadata().entrySet().stream().allMatch(entry -> matchesConstraint(entry.getValue(),
                execution.metadataValue(entry.getKey()), execution.executionTime(), essentialOnly));
    }

    private boolean matchesProperties(MethodExpression expression, AuthenticationMethodExecution execution, boolean essentialOnly) {
        return expression.properties().entrySet().stream().allMatch(entry -> matchesConstraint(entry.getValue(),
                execution.properties().map(properties -> properties.get(entry.getKey())), execution.executionTime(), essentialOnly));
    }

    private boolean matchesConstraint(ValueConstraint constraint, Optional<JsonNode> actual, Instant executionTime, boolean essentialOnly) {
        if (essentialOnly && !constraint.essential()) {
            return true;
        }
        if (!constraint.essential() && constraint.value().isEmpty() && constraint.values().isEmpty()
                && constraint.min().isEmpty() && constraint.max().isEmpty() && constraint.maxAge().isEmpty()) {
            // null means request the field when available; its absence is not a failed preference.
            return true;
        }
        if (actual.isEmpty()) {
            return false;
        }
        JsonNode actualValue = actual.get();
        if (constraint.value().isPresent() && !actualValue.equals(constraint.value().get())) {
            return false;
        }
        if (!constraint.values().isEmpty() && constraint.values().stream().noneMatch(actualValue::equals)) {
            return false;
        }
        if ((constraint.min().isPresent() || constraint.max().isPresent()) && !actualValue.isNumber()) {
            return false;
        }
        if (constraint.min().isPresent() && actualValue.decimalValue().compareTo(constraint.min().get()) < 0) {
            return false;
        }
        if (constraint.max().isPresent() && actualValue.decimalValue().compareTo(constraint.max().get()) > 0) {
            return false;
        }
        return constraint.maxAge().map(maxAge -> satisfiesMaxAge(executionTime, maxAge)).orElse(true);
    }

    private boolean satisfiesMaxAge(Instant executionTime, long maxAge) {
        Instant now = clock.instant();
        // Authentication times are represented with RFC 3339 precision, while
        // max_age is a whole-second freshness bound (as is OIDC auth_time).
        // Compare epoch seconds so max_age=0 can accept an execution that
        // completed in the current second instead of failing a few
        // milliseconds later when the final token is assembled.
        long executionSecond = executionTime.getEpochSecond();
        long nowSecond = now.getEpochSecond();
        return executionSecond <= nowSecond && executionSecond + maxAge >= nowSecond;
    }
}
