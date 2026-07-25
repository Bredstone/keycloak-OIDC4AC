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
package org.keycloak.protocol.oidc4ac.request;

import java.math.BigDecimal;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.keycloak.util.JsonSerialization;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

/** Parser and structural validator for the author-approved OIDC4AC grammar. */
public final class AmrDetailsRequestParser {

    private static final Set<String> CLAIM_FIELDS = Set.of("essential", "all_of", "one_of", "amr_identifier", "amr_metadata", "amr_properties");
    private static final Set<String> METHOD_FIELDS = Set.of("amr_identifier", "amr_metadata", "amr_properties");
    private static final Set<String> CONSTRAINT_FIELDS = Set.of("essential", "value", "values", "min", "max", "max_age");

    private AmrDetailsRequestParser() {
    }

    /**
     * Parses only the OIDC4AC portions of a {@code claims} parameter. A malformed
     * claims value is an invalid request once the experimental feature is enabled.
     */
    public static AmrDetailsClaimsRequest parseClaimsParameter(String claims) throws AmrDetailsRequestException {
        if (claims == null) {
            return new AmrDetailsClaimsRequest(Optional.empty(), Optional.empty());
        }

        JsonNode root;
        try {
            root = JsonSerialization.mapper.readTree(claims);
        } catch (JsonProcessingException e) {
            throw new AmrDetailsRequestException("The claims parameter is not valid JSON", e);
        }
        if (root == null || !root.isObject()) {
            throw new AmrDetailsRequestException("The claims parameter must be a JSON object");
        }

        return new AmrDetailsClaimsRequest(parseLocation((ObjectNode) root, "id_token"), parseLocation((ObjectNode) root, "userinfo"));
    }

    public static AmrDetailsClaimRequest parseClaimRequest(JsonNode node) throws AmrDetailsRequestException {
        if (node.isNull()) {
            return new AmrDetailsClaimRequest(false, Optional.empty());
        }
        if (!node.isObject()) {
            throw new AmrDetailsRequestException("amr_details must be null or a JSON object");
        }

        ObjectNode object = (ObjectNode) node;
        validateAllowedFields(object, CLAIM_FIELDS, "amr_details");
        boolean essential = parseBoolean(object.get("essential"), "amr_details.essential");
        int expressionCount = expressionCount(object);
        if (expressionCount == 0) {
            ensureClaimWithoutExpression(object);
            return new AmrDetailsClaimRequest(essential, Optional.empty());
        }
        if (expressionCount != 1) {
            throw new AmrDetailsRequestException("An expression node must contain exactly one operator");
        }
        return new AmrDetailsClaimRequest(essential, Optional.of(parseExpression(object, true)));
    }

    private static Optional<AmrDetailsClaimRequest> parseLocation(ObjectNode root, String location) throws AmrDetailsRequestException {
        JsonNode locationNode = root.get(location);
        if (locationNode == null) {
            return Optional.empty();
        }
        if (!locationNode.isObject()) {
            throw new AmrDetailsRequestException("The " + location + " claims request must be an object");
        }
        JsonNode amrDetails = locationNode.get("amr_details");
        return amrDetails == null ? Optional.empty() : Optional.of(parseClaimRequest(amrDetails));
    }

    private static AuthenticationMethodExpression parseExpression(ObjectNode object, boolean claimRoot) throws AmrDetailsRequestException {
        if (claimRoot) {
            validateAllowedFields(object, CLAIM_FIELDS, "amr_details");
        } else {
            validateAllowedFields(object, METHOD_FIELDS_WITH_LOGICAL, "expression");
            if (object.has("essential")) {
                throw new AmrDetailsRequestException("essential is only allowed on the claim or a local constraint");
            }
        }

        int expressionCount = expressionCount(object);
        if (expressionCount != 1) {
            throw new AmrDetailsRequestException("An expression node must contain exactly one operator");
        }
        if (object.has("all_of")) {
            ensureOnlyExpressionFields(object, "all_of", claimRoot);
            return new AllOfExpression(parseChildren(object.get("all_of"), "all_of"));
        }
        if (object.has("one_of")) {
            ensureOnlyExpressionFields(object, "one_of", claimRoot);
            return new OneOfExpression(parseChildren(object.get("one_of"), "one_of"));
        }
        return parseMethodExpression(object, claimRoot);
    }

    private static final Set<String> METHOD_FIELDS_WITH_LOGICAL = Set.of("all_of", "one_of", "amr_identifier", "amr_metadata", "amr_properties");

    private static List<AuthenticationMethodExpression> parseChildren(JsonNode node, String operator) throws AmrDetailsRequestException {
        if (!node.isArray() || node.isEmpty()) {
            throw new AmrDetailsRequestException(operator + " must be a non-empty array");
        }
        java.util.ArrayList<AuthenticationMethodExpression> children = new java.util.ArrayList<>();
        for (JsonNode child : node) {
            if (!child.isObject()) {
                throw new AmrDetailsRequestException(operator + " children must be JSON objects");
            }
            children.add(parseExpression((ObjectNode) child, false));
        }
        return children;
    }

    private static MethodExpression parseMethodExpression(ObjectNode object, boolean claimRoot) throws AmrDetailsRequestException {
        Set<String> allowed = claimRoot ? CLAIM_FIELDS : METHOD_FIELDS;
        validateAllowedFields(object, allowed, "method expression");
        if (!object.has("amr_identifier")) {
            throw new AmrDetailsRequestException("A method expression requires amr_identifier");
        }
        return new MethodExpression(parseIdentifierConstraint(object.get("amr_identifier")),
                parseConstraintObject(object.get("amr_metadata"), true), parseConstraintObject(object.get("amr_properties"), false));
    }

    private static IdentifierConstraint parseIdentifierConstraint(JsonNode node) throws AmrDetailsRequestException {
        if (!node.isObject()) {
            throw new AmrDetailsRequestException("amr_identifier must be an object");
        }
        ObjectNode object = (ObjectNode) node;
        validateAllowedFields(object, Set.of("value", "values"), "amr_identifier");
        boolean hasValue = object.has("value");
        boolean hasValues = object.has("values");
        if (hasValue == hasValues) {
            throw new AmrDetailsRequestException("amr_identifier requires exactly one of value or values");
        }

        Set<String> identifiers = new HashSet<>();
        if (hasValue) {
            identifiers.add(parseIdentifierValue(object.get("value")));
        } else {
            JsonNode values = object.get("values");
            if (!values.isArray() || values.isEmpty()) {
                throw new AmrDetailsRequestException("amr_identifier.values must be a non-empty array");
            }
            for (JsonNode value : values) {
                identifiers.add(parseIdentifierValue(value));
            }
        }
        return new IdentifierConstraint(identifiers);
    }

    private static String parseIdentifierValue(JsonNode node) throws AmrDetailsRequestException {
        if (!node.isTextual() || node.textValue().isBlank()) {
            throw new AmrDetailsRequestException("amr_identifier values must be non-blank strings");
        }
        return node.textValue();
    }

    private static java.util.Map<String, ValueConstraint> parseConstraintObject(JsonNode node, boolean metadata) throws AmrDetailsRequestException {
        if (node == null) {
            return java.util.Map.of();
        }
        if (!node.isObject()) {
            throw new AmrDetailsRequestException((metadata ? "amr_metadata" : "amr_properties") + " must be an object");
        }
        java.util.Map<String, ValueConstraint> constraints = new java.util.LinkedHashMap<>();
        Iterator<java.util.Map.Entry<String, JsonNode>> fields = node.fields();
        while (fields.hasNext()) {
            java.util.Map.Entry<String, JsonNode> field = fields.next();
            constraints.put(field.getKey(), parseValueConstraint(field.getValue(), metadata && "time".equals(field.getKey())));
        }
        return java.util.Map.copyOf(constraints);
    }

    private static ValueConstraint parseValueConstraint(JsonNode node, boolean timeConstraint) throws AmrDetailsRequestException {
        if (node.isNull()) {
            return ValueConstraint.requestedWhenAvailable();
        }
        if (!node.isObject()) {
            throw new AmrDetailsRequestException("A metadata or property constraint must be null or an object");
        }
        ObjectNode object = (ObjectNode) node;
        validateAllowedFields(object, CONSTRAINT_FIELDS, "constraint");
        boolean essential = parseBoolean(object.get("essential"), "constraint.essential");
        boolean hasValue = object.has("value");
        boolean hasValues = object.has("values");
        if (hasValue && hasValues) {
            throw new AmrDetailsRequestException("value and values are mutually exclusive");
        }

        Optional<JsonNode> value = Optional.empty();
        if (hasValue) {
            if (object.get("value").isNull()) {
                throw new AmrDetailsRequestException("constraint.value must not be null");
            }
            value = Optional.of(object.get("value").deepCopy());
        }

        List<JsonNode> values = List.of();
        if (hasValues) {
            JsonNode valuesNode = object.get("values");
            if (!valuesNode.isArray() || valuesNode.isEmpty()) {
                throw new AmrDetailsRequestException("constraint.values must be a non-empty array");
            }
            java.util.ArrayList<JsonNode> parsedValues = new java.util.ArrayList<>();
            for (JsonNode item : valuesNode) {
                if (item.isNull()) {
                    throw new AmrDetailsRequestException("constraint.values must not include null");
                }
                parsedValues.add(item.deepCopy());
            }
            values = List.copyOf(parsedValues);
        }

        Optional<BigDecimal> min = parseDecimal(object.get("min"), "min");
        Optional<BigDecimal> max = parseDecimal(object.get("max"), "max");
        Optional<Long> maxAge = parseMaxAge(object.get("max_age"), timeConstraint);
        try {
            return new ValueConstraint(essential, value, values, min, max, maxAge);
        } catch (IllegalArgumentException e) {
            throw new AmrDetailsRequestException(e.getMessage(), e);
        }
    }

    private static Optional<BigDecimal> parseDecimal(JsonNode node, String name) throws AmrDetailsRequestException {
        if (node == null) {
            return Optional.empty();
        }
        if (!node.isNumber()) {
            throw new AmrDetailsRequestException("constraint." + name + " must be a JSON number");
        }
        return Optional.of(node.decimalValue());
    }

    private static Optional<Long> parseMaxAge(JsonNode node, boolean timeConstraint) throws AmrDetailsRequestException {
        if (node == null) {
            return Optional.empty();
        }
        if (!timeConstraint) {
            throw new AmrDetailsRequestException("max_age is only valid for amr_metadata.time");
        }
        if (!node.isIntegralNumber() || !node.canConvertToLong() || node.longValue() < 0) {
            throw new AmrDetailsRequestException("max_age must be a non-negative integer");
        }
        return Optional.of(node.longValue());
    }

    private static boolean parseBoolean(JsonNode node, String name) throws AmrDetailsRequestException {
        if (node == null) {
            return false;
        }
        if (!node.isBoolean()) {
            throw new AmrDetailsRequestException(name + " must be a boolean");
        }
        return node.booleanValue();
    }

    private static int expressionCount(ObjectNode object) {
        int count = 0;
        if (object.has("all_of")) {
            count++;
        }
        if (object.has("one_of")) {
            count++;
        }
        if (object.has("amr_identifier")) {
            count++;
        }
        return count;
    }

    private static void ensureOnlyExpressionFields(ObjectNode object, String operator, boolean claimRoot) throws AmrDetailsRequestException {
        Set<String> allowed = claimRoot ? Set.of("essential", operator) : Set.of(operator);
        validateAllowedFields(object, allowed, operator + " expression");
    }

    private static void ensureClaimWithoutExpression(ObjectNode object) throws AmrDetailsRequestException {
        validateAllowedFields(object, Set.of("essential"), "amr_details");
    }

    private static void validateAllowedFields(ObjectNode object, Set<String> allowed, String location) throws AmrDetailsRequestException {
        Iterator<String> fields = object.fieldNames();
        while (fields.hasNext()) {
            String field = fields.next();
            if (!allowed.contains(field)) {
                throw new AmrDetailsRequestException("Unknown member in " + location);
            }
        }
    }
}
