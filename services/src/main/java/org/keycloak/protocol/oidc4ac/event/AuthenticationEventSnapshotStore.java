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
import java.util.ArrayList;
import java.util.Optional;

import org.keycloak.authentication.AuthenticatorUtil;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc4ac.model.AuthenticationEvent;
import org.keycloak.protocol.oidc4ac.model.AuthenticationMethodExecution;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * Keeps the current authorization event separate from the SSO source event and
 * from the immutable snapshot copied to an authenticated client session.
 */
public final class AuthenticationEventSnapshotStore {

    public static final String AUTH_SESSION_EVENT_NOTE = "oidc4ac.authentication-event";
    public static final String USER_SESSION_SSO_EVENT_NOTE = "oidc4ac.sso-authentication-event";
    public static final String CLIENT_SESSION_EVENT_NOTE = "oidc4ac.authentication-event";

    private AuthenticationEventSnapshotStore() {
    }

    public static void append(AuthenticationSessionModel authenticationSession, AuthenticationMethodExecution execution) {
        AuthenticationEvent existing = read(authenticationSession.getAuthNote(AUTH_SESSION_EVENT_NOTE)).orElseGet(() -> new AuthenticationEvent(java.util.List.of()));
        ArrayList<AuthenticationMethodExecution> executions = new ArrayList<>(existing.executions());
        executions.add(execution);
        authenticationSession.setAuthNote(AUTH_SESSION_EVENT_NOTE, AuthenticationEventSnapshotCodec.serialize(new AuthenticationEvent(executions)));
    }

    public static Optional<AuthenticationEvent> current(AuthenticationSessionModel authenticationSession) {
        return read(authenticationSession.getAuthNote(AUTH_SESSION_EVENT_NOTE));
    }

    public static Optional<AuthenticationEvent> client(AuthenticatedClientSessionModel clientSession) {
        return read(clientSession.getNote(CLIENT_SESSION_EVENT_NOTE));
    }

    /** The most recent event eligible for SSO reuse, retaining original execution times. */
    public static Optional<AuthenticationEvent> sso(UserSessionModel userSession) {
        return read(userSession.getNote(USER_SESSION_SSO_EVENT_NOTE));
    }

    /**
     * Captures a grant snapshot before OIDC protocol completion. An SSO reuse
     * copies the preserved source event without changing method timestamps.
     */
    public static Optional<AuthenticationEvent> persist(AuthenticationSessionModel authenticationSession,
            UserSessionModel userSession, AuthenticatedClientSessionModel clientSession) {
        Optional<AuthenticationEvent> current = current(authenticationSession).filter(event -> !event.executions().isEmpty());
        if (current.isPresent()) {
            String serialized = AuthenticationEventSnapshotCodec.serialize(current.get());
            userSession.setNote(USER_SESSION_SSO_EVENT_NOTE, serialized);
            clientSession.setNote(CLIENT_SESSION_EVENT_NOTE, serialized);
            return current;
        }
        if (!AuthenticatorUtil.isSSOAuthentication(authenticationSession)) {
            return Optional.empty();
        }
        String source = userSession.getNote(USER_SESSION_SSO_EVENT_NOTE);
        Optional<AuthenticationEvent> sourceEvent = read(source);
        sourceEvent.ifPresent(event -> clientSession.setNote(CLIENT_SESSION_EVENT_NOTE, AuthenticationEventSnapshotCodec.serialize(event)));
        return sourceEvent;
    }

    private static Optional<AuthenticationEvent> read(String serialized) {
        if (serialized == null) {
            return Optional.empty();
        }
        try {
            return Optional.of(AuthenticationEventSnapshotCodec.deserialize(serialized));
        } catch (IOException | IllegalArgumentException e) {
            return Optional.empty();
        }
    }
}
