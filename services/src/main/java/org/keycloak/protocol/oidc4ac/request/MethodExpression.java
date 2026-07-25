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

import java.util.Map;
import java.util.Objects;

/** A method inclusion requirement and its local metadata/property constraints. */
public record MethodExpression(IdentifierConstraint identifier, Map<String, ValueConstraint> metadata,
        Map<String, ValueConstraint> properties) implements AuthenticationMethodExpression {

    public MethodExpression {
        identifier = Objects.requireNonNull(identifier, "identifier");
        metadata = Map.copyOf(Objects.requireNonNull(metadata, "metadata"));
        properties = Map.copyOf(Objects.requireNonNull(properties, "properties"));
    }
}
