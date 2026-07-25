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
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * A direct metadata or method-property constraint. Non-essential constraints
 * remain best-effort preferences and therefore do not independently prevent a
 * method leaf from matching.
 */
public record ValueConstraint(boolean essential, Optional<JsonNode> value, List<JsonNode> values,
        Optional<BigDecimal> min, Optional<BigDecimal> max, Optional<Long> maxAge) {

    public ValueConstraint {
        value = Objects.requireNonNull(value, "value").map(JsonNode::deepCopy);
        List<JsonNode> copiedValues = new ArrayList<>();
        for (JsonNode candidate : Objects.requireNonNull(values, "values")) {
            copiedValues.add(candidate.deepCopy());
        }
        values = List.copyOf(copiedValues);
        min = Objects.requireNonNull(min, "min");
        max = Objects.requireNonNull(max, "max");
        maxAge = Objects.requireNonNull(maxAge, "maxAge");

        if (value.isPresent() && !values.isEmpty()) {
            throw new IllegalArgumentException("value and values are mutually exclusive");
        }
        if (min.isPresent() && max.isPresent() && min.get().compareTo(max.get()) > 0) {
            throw new IllegalArgumentException("min must not exceed max");
        }
        if (maxAge.isPresent() && maxAge.get() < 0) {
            throw new IllegalArgumentException("max_age must not be negative");
        }
    }

    public static ValueConstraint requestedWhenAvailable() {
        return new ValueConstraint(false, Optional.empty(), List.of(), Optional.empty(), Optional.empty(), Optional.empty());
    }
}
