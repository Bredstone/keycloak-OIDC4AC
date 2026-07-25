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

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;

/** A server-side, request-scoped ordered list of configured factor subflows. */
public record AuthenticationFactorPlan(String factorFlowId, List<String> executionIds) {

    public AuthenticationFactorPlan {
        factorFlowId = nonBlank(factorFlowId, "factorFlowId");
        executionIds = List.copyOf(Objects.requireNonNull(executionIds, "executionIds"));
        if (executionIds.stream().anyMatch(value -> value == null || value.isBlank())) {
            throw new IllegalArgumentException("executionIds must contain only non-blank values");
        }
        if (new LinkedHashSet<>(executionIds).size() != executionIds.size()) {
            throw new IllegalArgumentException("executionIds must not contain duplicates");
        }
    }

    private static String nonBlank(String value, String name) {
        Objects.requireNonNull(value, name);
        if (value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
        return value;
    }
}
