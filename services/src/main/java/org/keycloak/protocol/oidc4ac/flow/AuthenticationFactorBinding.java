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

import java.util.Objects;
import java.util.Set;

/**
 * A realm-administered binding from an AMR method to one child subflow of an
 * opt-in OIDC4AC factor container. The execution ID, rather than a provider
 * ID supplied by an RP, is what the eventual browser plan is allowed to run.
 */
public record AuthenticationFactorBinding(String executionId, String amrIdentifier, int priority,
        Set<String> propertyNames) {

    public AuthenticationFactorBinding {
        executionId = nonBlank(executionId, "executionId");
        amrIdentifier = nonBlank(amrIdentifier, "amrIdentifier");
        propertyNames = Set.copyOf(Objects.requireNonNull(propertyNames, "propertyNames"));
    }

    private static String nonBlank(String value, String name) {
        Objects.requireNonNull(value, name);
        if (value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
        return value;
    }
}
