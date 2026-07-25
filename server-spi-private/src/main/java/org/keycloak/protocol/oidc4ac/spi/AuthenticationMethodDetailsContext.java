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
import java.util.Objects;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * Context for describing a native authenticator that has already succeeded.
 * Native authentication remains responsible for verification. A non-null
 * selected credential ID is private execution context for an adapter to look
 * up the credential that was just verified; providers must never serialize or
 * disclose it.
 */
public record AuthenticationMethodDetailsContext(KeycloakSession session, RealmModel realm, UserModel user,
        AuthenticationSessionModel authenticationSession, UserSessionModel userSession, String authenticatorProviderId,
        String executionId, String credentialType, String selectedCredentialId, Instant executionTime) {

    public AuthenticationMethodDetailsContext {
        session = Objects.requireNonNull(session, "session");
        realm = Objects.requireNonNull(realm, "realm");
        user = Objects.requireNonNull(user, "user");
        authenticationSession = Objects.requireNonNull(authenticationSession, "authenticationSession");
        authenticatorProviderId = Objects.requireNonNull(authenticatorProviderId, "authenticatorProviderId");
        executionId = Objects.requireNonNull(executionId, "executionId");
        executionTime = Objects.requireNonNull(executionTime, "executionTime");
    }
}
