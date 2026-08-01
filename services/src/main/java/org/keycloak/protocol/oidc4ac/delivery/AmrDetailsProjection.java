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
package org.keycloak.protocol.oidc4ac.delivery;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.keycloak.protocol.oidc4ac.model.AuthenticationEvent;
import org.keycloak.protocol.oidc4ac.model.AuthenticationMethodExecution;
import org.keycloak.protocol.oidc4ac.disclosure.OIDC4ACDisclosurePolicy;
import org.keycloak.protocol.oidc4ac.request.AllOfExpression;
import org.keycloak.protocol.oidc4ac.request.AmrDetailsClaimRequest;
import org.keycloak.protocol.oidc4ac.request.AuthenticationMethodExpression;
import org.keycloak.protocol.oidc4ac.request.MethodExpression;
import org.keycloak.protocol.oidc4ac.request.OneOfExpression;
import org.keycloak.util.JsonSerialization;

/**
 * Delivery projection of a complete immutable event.
 *
 * <p>Every projection preserves every execution that the authorization relied
 * on, including its identifier and mandatory execution time. An expression
 * selects optional metadata and properties; it never selects which executions
 * are retained. A request without an expression receives all available
 * optional fields as well.</p>
 */
public final class AmrDetailsProjection {

    private AmrDetailsProjection() {
    }

    public static List<Map<String, Object>> project(AmrDetailsClaimRequest request, AuthenticationEvent event) {
        return project(request, event, OIDC4ACDisclosurePolicy.permissive());
    }

    public static List<Map<String, Object>> project(AmrDetailsClaimRequest request, AuthenticationEvent event,
            OIDC4ACDisclosurePolicy policy) {
        if (request.expression().isEmpty()) {
            return event.executions().stream().map(execution -> fullDetail(execution, policy)).toList();
        }

        Map<String, RequestedFields> requested = new LinkedHashMap<>();
        collect(request.expression().orElseThrow(), requested);
        List<Map<String, Object>> result = new ArrayList<>();
        for (AuthenticationMethodExecution execution : event.executions()) {
            // An expression constrains/evaluates the event but cannot redact a
            // method execution from the complete Authentication Event Claim.
            // Fields for an unmentioned method are empty, so only the required
            // identifier and time are delivered for that execution.
            result.add(requestedDetail(execution,
                    requested.getOrDefault(execution.amrIdentifier(), RequestedFields.empty()), policy));
        }
        return List.copyOf(result);
    }

    private static void collect(AuthenticationMethodExpression expression, Map<String, RequestedFields> requested) {
        if (expression instanceof AllOfExpression allOf) {
            allOf.children().forEach(child -> collect(child, requested));
            return;
        }
        if (expression instanceof OneOfExpression oneOf) {
            oneOf.children().forEach(child -> collect(child, requested));
            return;
        }
        MethodExpression method = (MethodExpression) expression;
        method.identifier().acceptedIdentifiers().forEach(identifier -> requested.merge(identifier,
                new RequestedFields(method.metadata().keySet(), method.properties().keySet()), RequestedFields::merge));
    }

    private static Map<String, Object> fullDetail(AuthenticationMethodExecution execution, OIDC4ACDisclosurePolicy policy) {
        Map<String, Object> detail = baseDetail(execution);
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("time", execution.executionTime().toString());
        execution.metadata().forEach((name, value) -> {
            if (policy.allowsByDefault("amr_metadata." + name)) {
                metadata.put(name, jsonValue(value));
            }
        });
        detail.put("amr_metadata", Map.copyOf(metadata));
        execution.properties().ifPresent(properties -> {
            Map<String, Object> values = new LinkedHashMap<>();
            properties.forEach((name, value) -> {
                if (policy.allowsByDefault("amr_properties." + name)) {
                    values.put(name, jsonValue(value));
                }
            });
            if (!values.isEmpty()) {
                detail.put("amr_properties", Map.copyOf(values));
            }
        });
        return Map.copyOf(detail);
    }

    private static Map<String, Object> requestedDetail(AuthenticationMethodExecution execution, RequestedFields fields,
            OIDC4ACDisclosurePolicy policy) {
        Map<String, Object> detail = baseDetail(execution);
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("time", execution.executionTime().toString());
        fields.metadata().forEach(name -> {
            if (policy.allows("amr_metadata." + name)) {
                execution.metadataValue(name).ifPresent(value -> metadata.put(name, jsonValue(value)));
            }
        });
        detail.put("amr_metadata", Map.copyOf(metadata));

        Map<String, Object> properties = new LinkedHashMap<>();
        execution.properties().ifPresent(actual -> fields.properties().forEach(name -> {
            if (policy.allows("amr_properties." + name) && actual.containsKey(name)) {
                properties.put(name, jsonValue(actual.get(name)));
            }
        }));
        if (!properties.isEmpty()) {
            detail.put("amr_properties", Map.copyOf(properties));
        }
        return Map.copyOf(detail);
    }

    private static Map<String, Object> baseDetail(AuthenticationMethodExecution execution) {
        Map<String, Object> detail = new LinkedHashMap<>();
        detail.put("amr_identifier", execution.amrIdentifier());
        return detail;
    }

    private static Object jsonValue(com.fasterxml.jackson.databind.JsonNode value) {
        return JsonSerialization.mapper.convertValue(value, Object.class);
    }

    private record RequestedFields(Set<String> metadata, Set<String> properties) {

        private static RequestedFields empty() {
            return new RequestedFields(Set.of(), Set.of());
        }

        private RequestedFields {
            metadata = Set.copyOf(metadata);
            properties = Set.copyOf(properties);
        }

        private RequestedFields merge(RequestedFields other) {
            Set<String> mergedMetadata = new LinkedHashSet<>(metadata);
            mergedMetadata.addAll(other.metadata);
            Set<String> mergedProperties = new LinkedHashSet<>(properties);
            mergedProperties.addAll(other.properties);
            return new RequestedFields(mergedMetadata, mergedProperties);
        }
    }
}
