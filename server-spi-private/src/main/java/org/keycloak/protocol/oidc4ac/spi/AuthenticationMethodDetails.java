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

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * A secret-free description of one successfully executed authentication method.
 *
 * <p>Providers must omit password hashes, salts, OTP secrets and counters,
 * credential identifiers, public and private key material, attestation data,
 * and any replayable authenticator data. A property map is absent when the
 * provider cannot truthfully return every unconditionally required property
 * for its method profile.</p>
 */
public record AuthenticationMethodDetails(String amrIdentifier, Instant executionTime, Map<String, Object> metadata,
        Optional<Map<String, Object>> properties) {

    public AuthenticationMethodDetails {
        amrIdentifier = Objects.requireNonNull(amrIdentifier, "amrIdentifier");
        executionTime = Objects.requireNonNull(executionTime, "executionTime");
        metadata = immutableObjectMap(metadata, "metadata");
        properties = Objects.requireNonNull(properties, "properties").map(values -> immutableObjectMap(values, "properties"));

        if (amrIdentifier.isBlank()) {
            throw new IllegalArgumentException("amrIdentifier must not be blank");
        }
    }

    private static Map<String, Object> immutableObjectMap(Map<String, Object> values, String name) {
        Objects.requireNonNull(values, name);
        return values.entrySet().stream()
                .collect(java.util.stream.Collectors.toUnmodifiableMap(Map.Entry::getKey,
                        entry -> immutableJsonValue(entry.getValue())));
    }

    @SuppressWarnings("unchecked")
    private static Object immutableJsonValue(Object value) {
        if (value instanceof String || value instanceof Boolean || value instanceof Number) {
            return value;
        }
        if (value instanceof Map<?, ?> map) {
            return map.entrySet().stream().collect(java.util.stream.Collectors.toUnmodifiableMap(
                    entry -> {
                        if (!(entry.getKey() instanceof String key)) {
                            throw new IllegalArgumentException("JSON object keys must be strings");
                        }
                        return key;
                    }, entry -> immutableJsonValue(entry.getValue())));
        }
        if (value instanceof List<?> list) {
            return list.stream().map(AuthenticationMethodDetails::immutableJsonValue).toList();
        }
        throw new IllegalArgumentException("Details values must be non-null JSON-compatible values");
    }
}
