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
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import org.keycloak.OAuth2Constants;
import org.keycloak.authentication.AuthenticatorUtil;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.utils.SessionExpirationUtils;
import org.keycloak.protocol.oidc4ac.OIDC4ACConstants;
import org.keycloak.protocol.oidc4ac.model.AuthenticationEvent;
import org.keycloak.protocol.oidc4ac.model.AuthenticationMethodExecution;
import org.keycloak.protocol.oidc4ac.request.AmrDetailsRequestException;
import org.keycloak.protocol.oidc4ac.request.AmrDetailsRequestParser;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * Keeps the current authorization event separate from the SSO source event and
 * from an immutable snapshot keyed by an opaque authorization-grant handle.
 */
public final class AuthenticationEventSnapshotStore {

    public static final String AUTH_SESSION_EVENT_NOTE = "oidc4ac.authentication-event";
    public static final String USER_SESSION_SSO_EVENT_NOTE = "oidc4ac.sso-authentication-event";
    public static final String GRANT_ID_ATTRIBUTE = "oidc4ac.grant-id";

    private static final String GRANT_SNAPSHOT_PREFIX = "oidc4ac-grant:";
    private static final String EVENT_NOTE = "event";
    private static final String CLAIMS_NOTE = "claims";
    private static final String REALM_ID_NOTE = "realm-id";
    private static final String CLIENT_ID_NOTE = "client-id";
    private static final String USER_ID_NOTE = "user-id";

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

    /** The most recent event eligible for SSO reuse, retaining original execution times. */
    public static Optional<AuthenticationEvent> sso(UserSessionModel userSession) {
        return read(userSession.getNote(USER_SESSION_SSO_EVENT_NOTE));
    }

    /**
     * Captures a grant snapshot before OIDC protocol completion. The record is
     * keyed independently of the authenticated client session, which Keycloak
     * shares across concurrent authorizations for one user/client pair.
     *
     * <p>An SSO reuse copies the preserved source event without changing method
     * timestamps. The SSO source is session-scoped by design; each resulting
     * authorization still receives a distinct immutable grant snapshot.</p>
     */
    public static Optional<String> persist(KeycloakSession session, AuthenticationSessionModel authenticationSession,
            UserSessionModel userSession, AuthenticatedClientSessionModel clientSession, String claims) {
        Optional<AuthenticationEvent> current = current(authenticationSession).filter(event -> !event.executions().isEmpty());
        Optional<AuthenticationEvent> event;
        if (current.isPresent()) {
            String serialized = AuthenticationEventSnapshotCodec.serialize(current.get());
            userSession.setNote(USER_SESSION_SSO_EVENT_NOTE, serialized);
            event = current;
        } else if (AuthenticatorUtil.isSSOAuthentication(authenticationSession)) {
            event = sso(userSession);
        } else {
            event = Optional.empty();
        }

        if (event.isEmpty() || !requestsAmrDetails(claims)) {
            return Optional.empty();
        }

        String grantId = SecretGenerator.getInstance().generateSecureID();
        Map<String, String> notes = new HashMap<>();
        notes.put(EVENT_NOTE, AuthenticationEventSnapshotCodec.serialize(event.orElseThrow()));
        if (claims != null) {
            notes.put(CLAIMS_NOTE, claims);
        }
        notes.put(REALM_ID_NOTE, userSession.getRealm().getId());
        notes.put(CLIENT_ID_NOTE, clientSession.getClient().getId());
        notes.put(USER_ID_NOTE, userSession.getUser().getId());
        session.singleUseObjects().put(GRANT_SNAPSHOT_PREFIX + grantId,
                grantLifespanSeconds(authenticationSession, userSession, clientSession), Map.copyOf(notes));
        return Optional.of(grantId);
    }

    /** Associates the current request context with a previously created grant snapshot. */
    public static void attachGrant(ClientSessionContext clientSessionContext, String grantId) {
        if (grantId != null && !grantId.isBlank()) {
            clientSessionContext.setAttribute(GRANT_ID_ATTRIBUTE, grantId);
        }
    }

    /** Adds the opaque grant handle to an internal token; the snapshot itself is never tokenized. */
    public static void bindToken(JsonWebToken token, ClientSessionContext clientSessionContext) {
        Optional.ofNullable(clientSessionContext.getAttribute(GRANT_ID_ATTRIBUTE, String.class))
                .filter(grantId -> !grantId.isBlank())
                .ifPresent(grantId -> token.setOtherClaims(OIDC4ACConstants.GRANT_ID, grantId));
    }

    /** Preserves the opaque handle when a refresh token is derived from its access token. */
    public static void bindToken(JsonWebToken token, JsonWebToken sourceToken) {
        Object grantId = sourceToken.getOtherClaims().get(OIDC4ACConstants.GRANT_ID);
        if (grantId instanceof String value && !value.isBlank()) {
            token.setOtherClaims(OIDC4ACConstants.GRANT_ID, value);
        }
    }

    /** Restores the opaque grant handle from a verified internal token. */
    public static void attachGrant(ClientSessionContext clientSessionContext, JsonWebToken token) {
        Object grantId = token.getOtherClaims().get(OIDC4ACConstants.GRANT_ID);
        if (grantId instanceof String value) {
            attachGrant(clientSessionContext, value);
        }
    }

    /**
     * Loads a snapshot only when its opaque handle is bound to this realm,
     * client, and user. A handle from another grant can therefore never be
     * substituted across sessions.
     */
    public static Optional<AuthenticationEventGrantSnapshot> grant(KeycloakSession session,
            ClientSessionContext clientSessionContext) {
        String grantId = clientSessionContext.getAttribute(GRANT_ID_ATTRIBUTE, String.class);
        if (grantId == null || grantId.isBlank()) {
            return Optional.empty();
        }

        Map<String, String> notes = session.singleUseObjects().get(GRANT_SNAPSHOT_PREFIX + grantId);
        if (notes == null) {
            return Optional.empty();
        }

        AuthenticatedClientSessionModel clientSession = clientSessionContext.getClientSession();
        UserSessionModel userSession = clientSession.getUserSession();
        if (!userSession.getRealm().getId().equals(notes.get(REALM_ID_NOTE))
                || !clientSession.getClient().getId().equals(notes.get(CLIENT_ID_NOTE))
                || !userSession.getUser().getId().equals(notes.get(USER_ID_NOTE))) {
            return Optional.empty();
        }
        return read(notes.get(EVENT_NOTE)).map(event -> new AuthenticationEventGrantSnapshot(event,
                Optional.ofNullable(notes.get(CLAIMS_NOTE))));
    }

    private static boolean requestsAmrDetails(String claims) {
        try {
            var request = AmrDetailsRequestParser.parseClaimsParameter(claims);
            return request.idToken().isPresent() || request.userInfo().isPresent();
        } catch (AmrDetailsRequestException e) {
            // The authorization endpoint check rejects malformed requests. Do
            // not create a record if this method is reached through another
            // protocol path with invalid data.
            return false;
        }
    }

    private static long grantLifespanSeconds(AuthenticationSessionModel authenticationSession,
            UserSessionModel userSession, AuthenticatedClientSessionModel clientSession) {
        RealmModel realm = userSession.getRealm();
        long now = System.currentTimeMillis();
        long onlineExpiry = SessionExpirationUtils.calculateClientSessionMaxLifespanTimestamp(false,
                userSession.isRememberMe(), clientSession.getStarted() * 1000L, userSession.getStarted() * 1000L,
                realm, clientSession.getClient());
        long lifespan = secondsUntil(onlineExpiry, now);

        String scope = authenticationSession.getClientNote(OAuth2Constants.SCOPE);
        if (scope != null && java.util.Arrays.asList(scope.split(" ")).contains(OAuth2Constants.OFFLINE_ACCESS)) {
            long offlineExpiry = SessionExpirationUtils.calculateClientSessionMaxLifespanTimestamp(true,
                    userSession.isRememberMe(), clientSession.getStarted() * 1000L, userSession.getStarted() * 1000L,
                    realm, clientSession.getClient());
            if (offlineExpiry <= 0) {
                // Keycloak permits an unbounded offline session. Keep the
                // secret-free snapshot for the corresponding maximum duration
                // accepted by the storage provider rather than silently losing
                // grant isolation on a later offline refresh.
                return Integer.MAX_VALUE;
            }
            lifespan = Math.max(lifespan, secondsUntil(offlineExpiry, now));
        }
        return Math.max(1, lifespan);
    }

    private static long secondsUntil(long expiryMillis, long nowMillis) {
        if (expiryMillis <= nowMillis) {
            return 1;
        }
        return Math.max(1, (expiryMillis - nowMillis + 999) / 1000);
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
