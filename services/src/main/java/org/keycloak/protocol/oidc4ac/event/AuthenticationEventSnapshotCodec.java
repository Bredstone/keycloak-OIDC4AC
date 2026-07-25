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
package org.keycloak.protocol.oidc4ac.event;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.keycloak.protocol.oidc4ac.model.AuthenticationEvent;
import org.keycloak.protocol.oidc4ac.model.AuthenticationMethodExecution;
import org.keycloak.protocol.oidc4ac.spi.AuthenticationMethodDetails;
import org.keycloak.util.JsonSerialization;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

/** Canonical, secret-free serialization for an immutable OIDC4AC event. */
public final class AuthenticationEventSnapshotCodec {

    private AuthenticationEventSnapshotCodec() {
    }

    public static AuthenticationMethodExecution fromDetails(AuthenticationMethodDetails details) {
        Map<String, JsonNode> metadata = jsonNodeMap(details.metadata());
        if (metadata.containsKey("time")) {
            throw new IllegalArgumentException("Provider metadata must not include time");
        }
        Optional<Map<String, JsonNode>> properties = details.properties().map(AuthenticationEventSnapshotCodec::jsonNodeMap);
        return new AuthenticationMethodExecution(details.amrIdentifier(), details.executionTime(), metadata, properties);
    }

    public static String serialize(AuthenticationEvent event) {
        ArrayNode root = JsonSerialization.mapper.createArrayNode();
        for (AuthenticationMethodExecution execution : event.executions()) {
            ObjectNode detail = root.addObject();
            detail.put("amr_identifier", execution.amrIdentifier());
            ObjectNode metadata = detail.putObject("amr_metadata");
            metadata.put("time", execution.executionTime().toString());
            execution.metadata().forEach((name, value) -> metadata.set(name, value.deepCopy()));
            execution.properties().ifPresent(properties -> {
                ObjectNode propertyNode = detail.putObject("amr_properties");
                properties.forEach((name, value) -> propertyNode.set(name, value.deepCopy()));
            });
        }
        try {
            return JsonSerialization.mapper.writeValueAsString(root);
        } catch (IOException e) {
            throw new IllegalStateException("Could not serialize OIDC4AC Authentication Event", e);
        }
    }

    public static AuthenticationEvent deserialize(String serialized) throws IOException {
        JsonNode root = JsonSerialization.mapper.readTree(serialized);
        if (root == null || !root.isArray()) {
            throw new IOException("The Authentication Event snapshot must be an array");
        }
        List<AuthenticationMethodExecution> executions = new ArrayList<>();
        for (JsonNode detail : root) {
            if (!detail.isObject()) {
                throw new IOException("An Authentication Event detail must be an object");
            }
            JsonNode identifier = detail.get("amr_identifier");
            JsonNode metadata = detail.get("amr_metadata");
            if (identifier == null || !identifier.isTextual() || metadata == null || !metadata.isObject()) {
                throw new IOException("An Authentication Event detail is incomplete");
            }
            JsonNode time = metadata.get("time");
            if (time == null || !time.isTextual()) {
                throw new IOException("An Authentication Event detail does not contain a time");
            }
            Instant executionTime;
            try {
                executionTime = Instant.parse(time.textValue());
            } catch (RuntimeException e) {
                throw new IOException("An Authentication Event detail contains an invalid time", e);
            }

            Map<String, JsonNode> metadataValues = objectValues((ObjectNode) metadata, "time");
            JsonNode properties = detail.get("amr_properties");
            Optional<Map<String, JsonNode>> propertyValues;
            if (properties == null) {
                propertyValues = Optional.empty();
            } else if (properties.isObject()) {
                propertyValues = Optional.of(objectValues((ObjectNode) properties));
            } else {
                throw new IOException("amr_properties must be an object when present");
            }
            executions.add(new AuthenticationMethodExecution(identifier.textValue(), executionTime, metadataValues, propertyValues));
        }
        return new AuthenticationEvent(executions);
    }

    private static Map<String, JsonNode> jsonNodeMap(Map<String, Object> values) {
        Map<String, JsonNode> result = new LinkedHashMap<>();
        values.forEach((name, value) -> result.put(name, JsonSerialization.mapper.valueToTree(value)));
        return Map.copyOf(result);
    }

    private static Map<String, JsonNode> objectValues(ObjectNode object, String... excluded) {
        java.util.Set<String> excludedNames = java.util.Set.of(excluded);
        Map<String, JsonNode> result = new LinkedHashMap<>();
        object.fields().forEachRemaining(entry -> {
            if (!excludedNames.contains(entry.getKey())) {
                result.put(entry.getKey(), entry.getValue().deepCopy());
            }
        });
        return Map.copyOf(result);
    }
}
