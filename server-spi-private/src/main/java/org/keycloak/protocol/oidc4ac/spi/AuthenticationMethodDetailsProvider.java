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

import java.util.Collection;
import java.util.Optional;

import org.keycloak.provider.Provider;

/**
 * Experimental contract for obtaining safe OIDC4AC details after an
 * authenticator has succeeded. Implementations must not authenticate the user
 * or expose credential secrets through this contract.
 */
public interface AuthenticationMethodDetailsProvider extends Provider {

    Collection<AuthenticationMethodCapability> getCapabilities();

    boolean supports(AuthenticationMethodDetailsContext context);

    Optional<AuthenticationMethodDetails> describeSuccessfulExecution(AuthenticationMethodDetailsContext context);
}
