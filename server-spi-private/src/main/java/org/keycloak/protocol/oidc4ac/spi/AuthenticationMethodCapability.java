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
package org.keycloak.protocol.oidc4ac.spi;

import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Safe OIDC4AC discovery capabilities for one authentication method.
 *
 * <p>Only a finite, closed string vocabulary belongs in
 * {@link #finiteStringPropertyValues()}. Open domains, numbers, timestamps,
 * booleans, objects, and identifiers are represented by the property name
 * alone and are not enumerated.</p>
 */
public record AuthenticationMethodCapability(String amrIdentifier, Set<String> propertyNames,
        Map<String, Set<String>> finiteStringPropertyValues) {

    public AuthenticationMethodCapability {
        amrIdentifier = Objects.requireNonNull(amrIdentifier, "amrIdentifier");
        propertyNames = Set.copyOf(propertyNames);
        finiteStringPropertyValues = finiteStringPropertyValues.entrySet().stream()
                .collect(java.util.stream.Collectors.toUnmodifiableMap(Map.Entry::getKey, entry -> Set.copyOf(entry.getValue())));

        if (amrIdentifier.isBlank()) {
            throw new IllegalArgumentException("amrIdentifier must not be blank");
        }
        if (!propertyNames.containsAll(finiteStringPropertyValues.keySet())) {
            throw new IllegalArgumentException("A finite value list requires an advertised property");
        }
    }
}
