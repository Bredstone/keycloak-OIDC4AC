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

/** Mutable server-side cursor for an otherwise immutable factor plan. */
public record AuthenticationFactorPlanProgress(String factorFlowId, int stepIndex, int branchIndex, String executionId) {

    public AuthenticationFactorPlanProgress {
        factorFlowId = Objects.requireNonNull(factorFlowId, "factorFlowId");
        if (factorFlowId.isBlank() || stepIndex < 0 || branchIndex < 0) {
            throw new IllegalArgumentException("A factor-plan progress cursor is invalid");
        }
    }
}
