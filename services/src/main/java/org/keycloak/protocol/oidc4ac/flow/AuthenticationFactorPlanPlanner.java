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

import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;

import org.keycloak.protocol.oidc4ac.request.AllOfExpression;
import org.keycloak.protocol.oidc4ac.request.AmrDetailsClaimRequest;
import org.keycloak.protocol.oidc4ac.request.AmrDetailsClaimsRequest;
import org.keycloak.protocol.oidc4ac.request.AuthenticationMethodExpression;
import org.keycloak.protocol.oidc4ac.request.MethodExpression;
import org.keycloak.protocol.oidc4ac.request.OneOfExpression;

/**
 * Converts request expressions into a policy-ordered subset of already
 * configured factor subflows. It never changes a realm flow or treats an RP
 * supplied identifier as an executable provider ID.
 */
public final class AuthenticationFactorPlanPlanner {

    private static final Comparator<AuthenticationFactorBinding> POLICY_ORDER = Comparator
            .comparingInt(AuthenticationFactorBinding::priority)
            .thenComparing(AuthenticationFactorBinding::executionId);

    public AuthenticationFactorPlanResult plan(AmrDetailsClaimsRequest requests, String factorFlowId,
            Collection<AuthenticationFactorBinding> availableBindings) {
        List<AuthenticationFactorBinding> bindings = availableBindings.stream().sorted(POLICY_ORDER).toList();
        List<AuthenticationFactorPlanStep> steps = new java.util.ArrayList<>();
        boolean essentialRequirementsUnplannable = false;

        for (AmrDetailsClaimRequest request : List.of(requests.idToken(), requests.userInfo()).stream()
                .flatMap(Optional::stream).toList()) {
            if (request.expression().isEmpty()) {
                continue;
            }
            List<List<AuthenticationFactorBinding>> branches = branches(request.expression().orElseThrow(), bindings);
            if (branches.isEmpty()) {
                essentialRequirementsUnplannable |= request.essential();
            } else {
                steps.add(new AuthenticationFactorPlanStep(branches.stream().sorted(this::compareBranches)
                        .map(branch -> new AuthenticationFactorPlanBranch(branch.stream()
                                .map(AuthenticationFactorBinding::executionId).toList())).toList()));
            }
        }

        return new AuthenticationFactorPlanResult(new AuthenticationFactorPlan(factorFlowId, steps),
                essentialRequirementsUnplannable);
    }

    private List<List<AuthenticationFactorBinding>> branches(AuthenticationMethodExpression expression,
            List<AuthenticationFactorBinding> bindings) {
        if (expression instanceof AllOfExpression allOf) {
            List<List<AuthenticationFactorBinding>> result = List.of(List.of());
            for (AuthenticationMethodExpression child : allOf.children()) {
                result = combine(result, branches(child, bindings));
                if (result.isEmpty()) {
                    return List.of();
                }
            }
            return result;
        }
        if (expression instanceof OneOfExpression oneOf) {
            return oneOf.children().stream().flatMap(child -> branches(child, bindings).stream()).distinct().toList();
        }
        return methodBranches((MethodExpression) expression, bindings);
    }

    private List<List<AuthenticationFactorBinding>> methodBranches(MethodExpression expression,
            List<AuthenticationFactorBinding> bindings) {
        return bindings.stream()
                .filter(binding -> expression.identifier().matches(binding.amrIdentifier()))
                .filter(binding -> expression.properties().entrySet().stream()
                        .filter(entry -> entry.getValue().essential())
                        .allMatch(entry -> binding.propertyNames().contains(entry.getKey())))
                .map(binding -> List.of(binding)).toList();
    }

    private List<List<AuthenticationFactorBinding>> combine(List<List<AuthenticationFactorBinding>> left,
            List<List<AuthenticationFactorBinding>> right) {
        if (left.isEmpty() || right.isEmpty()) {
            return List.of();
        }
        List<List<AuthenticationFactorBinding>> result = new java.util.ArrayList<>();
        for (List<AuthenticationFactorBinding> leftBranch : left) {
            for (List<AuthenticationFactorBinding> rightBranch : right) {
                // Each method leaf represents one execution.  Do not collapse
                // two occurrences of the same leaf onto one configured
                // binding: a repeated request needs two distinct executions
                // (and therefore two independent authentication events).
                if (rightBranch.stream().anyMatch(leftBranch::contains)) {
                    continue;
                }
                LinkedHashSet<AuthenticationFactorBinding> merged = new LinkedHashSet<>(leftBranch);
                merged.addAll(rightBranch);
                result.add(merged.stream().sorted(POLICY_ORDER).toList());
            }
        }
        return result.stream().distinct().toList();
    }

    /** A lower realm priority wins; factor count and IDs make the choice deterministic. */
    private int compareBranches(List<AuthenticationFactorBinding> left, List<AuthenticationFactorBinding> right) {
        int priority = Integer.compare(left.stream().mapToInt(AuthenticationFactorBinding::priority).max().orElse(0),
                right.stream().mapToInt(AuthenticationFactorBinding::priority).max().orElse(0));
        if (priority != 0) {
            return priority;
        }
        int count = Integer.compare(left.size(), right.size());
        if (count != 0) {
            return count;
        }
        List<String> leftIds = left.stream().map(AuthenticationFactorBinding::executionId).toList();
        List<String> rightIds = right.stream().map(AuthenticationFactorBinding::executionId).toList();
        for (int i = 0; i < leftIds.size(); i++) {
            int comparison = leftIds.get(i).compareTo(rightIds.get(i));
            if (comparison != 0) {
                return comparison;
            }
        }
        return 0;
    }
}
