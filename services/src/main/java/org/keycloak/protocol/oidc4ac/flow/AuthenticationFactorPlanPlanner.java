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
import java.util.Set;

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
        LinkedHashSet<AuthenticationFactorBinding> selected = new LinkedHashSet<>();
        boolean essentialRequirementsUnplannable = false;

        for (AmrDetailsClaimRequest request : List.of(requests.idToken(), requests.userInfo()).stream()
                .flatMap(Optional::stream).toList()) {
            if (request.expression().isEmpty()) {
                continue;
            }
            Optional<Set<AuthenticationFactorBinding>> candidate = select(request.expression().orElseThrow(), bindings);
            if (candidate.isEmpty()) {
                essentialRequirementsUnplannable |= request.essential();
            } else {
                selected.addAll(candidate.orElseThrow());
            }
        }

        List<String> executionIds = selected.stream().sorted(POLICY_ORDER)
                .map(AuthenticationFactorBinding::executionId).toList();
        return new AuthenticationFactorPlanResult(new AuthenticationFactorPlan(factorFlowId, executionIds),
                essentialRequirementsUnplannable);
    }

    private Optional<Set<AuthenticationFactorBinding>> select(AuthenticationMethodExpression expression,
            List<AuthenticationFactorBinding> bindings) {
        if (expression instanceof AllOfExpression allOf) {
            LinkedHashSet<AuthenticationFactorBinding> result = new LinkedHashSet<>();
            for (AuthenticationMethodExpression child : allOf.children()) {
                Optional<Set<AuthenticationFactorBinding>> selectedChild = select(child, bindings);
                if (selectedChild.isEmpty()) {
                    return Optional.empty();
                }
                result.addAll(selectedChild.orElseThrow());
            }
            return Optional.of(Set.copyOf(result));
        }
        if (expression instanceof OneOfExpression oneOf) {
            return oneOf.children().stream().map(child -> select(child, bindings)).flatMap(Optional::stream)
                    .min(this::compareBranches);
        }
        return selectMethod((MethodExpression) expression, bindings);
    }

    private Optional<Set<AuthenticationFactorBinding>> selectMethod(MethodExpression expression,
            List<AuthenticationFactorBinding> bindings) {
        return bindings.stream()
                .filter(binding -> expression.identifier().matches(binding.amrIdentifier()))
                .filter(binding -> expression.properties().entrySet().stream()
                        .filter(entry -> entry.getValue().essential())
                        .allMatch(entry -> binding.propertyNames().contains(entry.getKey())))
                .findFirst().map(binding -> Set.of(binding));
    }

    /** A lower realm priority wins; factor count and IDs make the choice deterministic. */
    private int compareBranches(Set<AuthenticationFactorBinding> first, Set<AuthenticationFactorBinding> second) {
        List<AuthenticationFactorBinding> left = first.stream().sorted(POLICY_ORDER).toList();
        List<AuthenticationFactorBinding> right = second.stream().sorted(POLICY_ORDER).toList();
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
