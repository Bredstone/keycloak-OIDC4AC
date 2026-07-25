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
package org.keycloak.protocol.oidc4ac.model;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * One actual authentication method execution. Metadata excludes {@code time},
 * which is represented by {@link #executionTime()} and always serialized.
 */
public record AuthenticationMethodExecution(String amrIdentifier, Instant executionTime, Map<String, JsonNode> metadata,
        Optional<Map<String, JsonNode>> properties) {

    public AuthenticationMethodExecution {
        amrIdentifier = Objects.requireNonNull(amrIdentifier, "amrIdentifier");
        executionTime = Objects.requireNonNull(executionTime, "executionTime");
        metadata = immutableJsonMap(metadata, "metadata");
        properties = Objects.requireNonNull(properties, "properties").map(values -> immutableJsonMap(values, "properties"));

        if (amrIdentifier.isBlank()) {
            throw new IllegalArgumentException("amrIdentifier must not be blank");
        }
        if (metadata.containsKey("time")) {
            throw new IllegalArgumentException("metadata time is represented by executionTime");
        }
    }

    public Optional<JsonNode> metadataValue(String name) {
        if ("time".equals(name)) {
            return Optional.of(com.fasterxml.jackson.databind.node.TextNode.valueOf(executionTime.toString()));
        }
        return Optional.ofNullable(metadata.get(name));
    }

    private static Map<String, JsonNode> immutableJsonMap(Map<String, JsonNode> values, String name) {
        Objects.requireNonNull(values, name);
        return values.entrySet().stream().collect(java.util.stream.Collectors.toUnmodifiableMap(Map.Entry::getKey,
                entry -> Objects.requireNonNull(entry.getValue(), name + " values must not be null").deepCopy()));
    }
}
