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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

import java.lang.reflect.Proxy;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.Test;
import org.keycloak.common.Profile;
import org.keycloak.common.profile.CommaSeparatedListProfileConfigResolver;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc4ac.delivery.AmrDetailsDeliveryService;
import org.keycloak.protocol.oidc4ac.model.AuthenticationEvent;
import org.keycloak.protocol.oidc4ac.model.AuthenticationMethodExecution;
import org.keycloak.representations.AccessToken;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.services.managers.AuthenticationManager;

public class AuthenticationEventSnapshotStoreTest {

    private static final String CLAIMS = """
            {"id_token":{"amr_details":null},"userinfo":{"amr_details":null}}
            """;

    @Test
    public void keepsConcurrentGrantsSeparatedFromTheSharedClientSession() {
        Map<String, Map<String, String>> snapshots = new HashMap<>();
        KeycloakSession session = keycloakSession(snapshots);
        UserSessionModel userSession = userSession("user-a");
        AuthenticatedClientSessionModel clientSession = clientSession(userSession);

        String firstGrant = AuthenticationEventSnapshotStore.persist(session,
                authenticationSession(event("pwd", "2026-07-25T12:00:00Z"), CLAIMS), userSession, clientSession, CLAIMS).orElseThrow();
        String secondGrant = AuthenticationEventSnapshotStore.persist(session,
                authenticationSession(event("otp", "2026-07-25T12:01:00Z"), CLAIMS), userSession, clientSession, CLAIMS).orElseThrow();

        assertNotEquals(firstGrant, secondGrant);
        assertEquals(2, snapshots.size());

        ClientSessionContext firstContext = clientSessionContext(clientSession);
        AuthenticationEventSnapshotStore.attachGrant(firstContext, firstGrant);
        AuthenticationEventGrantSnapshot first = AuthenticationEventSnapshotStore.grant(session, firstContext).orElseThrow();
        assertEquals("pwd", first.event().executions().get(0).amrIdentifier());
        assertEquals(CLAIMS, first.claims().orElseThrow());

        ClientSessionContext secondContext = clientSessionContext(clientSession);
        AuthenticationEventSnapshotStore.attachGrant(secondContext, secondGrant);
        AuthenticationEventGrantSnapshot second = AuthenticationEventSnapshotStore.grant(session, secondContext).orElseThrow();
        assertEquals("otp", second.event().executions().get(0).amrIdentifier());
    }

    @Test
    public void carriesOnlyAnOpaqueHandleAndRejectsAHandleForAnotherUser() {
        Map<String, Map<String, String>> snapshots = new HashMap<>();
        KeycloakSession session = keycloakSession(snapshots);
        UserSessionModel userSession = userSession("user-a");
        AuthenticatedClientSessionModel clientSession = clientSession(userSession);
        String grantId = AuthenticationEventSnapshotStore.persist(session,
                authenticationSession(event("pwd", "2026-07-25T12:00:00Z"), CLAIMS), userSession, clientSession, CLAIMS).orElseThrow();

        ClientSessionContext issuingContext = clientSessionContext(clientSession);
        AuthenticationEventSnapshotStore.attachGrant(issuingContext, grantId);
        AccessToken accessToken = new AccessToken();
        AuthenticationEventSnapshotStore.bindToken(accessToken, issuingContext);

        ClientSessionContext sameUserContext = clientSessionContext(clientSession);
        AuthenticationEventSnapshotStore.attachGrant(sameUserContext, accessToken);
        assertTrue(AuthenticationEventSnapshotStore.grant(session, sameUserContext).isPresent());
        assertFalse(accessToken.getOtherClaims().containsKey("event"));

        ClientSessionContext anotherUserContext = clientSessionContext(clientSession(userSession("user-b")));
        AuthenticationEventSnapshotStore.attachGrant(anotherUserContext, accessToken);
        assertFalse(AuthenticationEventSnapshotStore.grant(session, anotherUserContext).isPresent());
    }

    @Test
    public void deliveryUsesTheGrantClaimsInsteadOfTheSharedClientSessionNotes() {
        Profile.configure(new CommaSeparatedListProfileConfigResolver(Profile.Feature.OIDC4AC.getVersionedKey(), ""));
        try {
            Map<String, Map<String, String>> snapshots = new HashMap<>();
            KeycloakSession session = keycloakSession(snapshots);
            UserSessionModel userSession = userSession("user-a");
            AuthenticatedClientSessionModel clientSession = clientSession(userSession);
            String grantId = AuthenticationEventSnapshotStore.persist(session,
                    authenticationSession(event("pwd", "2026-07-25T12:00:00Z"), CLAIMS), userSession, clientSession, CLAIMS).orElseThrow();
            ClientSessionContext context = clientSessionContext(clientSession);
            AuthenticationEventSnapshotStore.attachGrant(context, grantId);

            AccessToken idToken = new AccessToken();
            AmrDetailsDeliveryService.applyToIdToken(session, idToken, context);

            List<?> details = (List<?>) idToken.getOtherClaims().get("amr_details");
            assertEquals("pwd", ((Map<?, ?>) details.get(0)).get("amr_identifier"));
        } finally {
            Profile.reset();
        }
    }

    @Test
    public void reusesSsoEventWhenAuthenticationNoteWasClearedBeforeSnapshotPersistence() {
        Map<String, Map<String, String>> snapshots = new HashMap<>();
        KeycloakSession session = keycloakSession(snapshots);
        UserSessionModel userSession = userSession("user-a");
        AuthenticatedClientSessionModel clientSession = clientSession(userSession);

        AuthenticationEventSnapshotStore.persist(session,
                authenticationSession(event("pwd", "2026-07-25T12:00:00Z"), CLAIMS), userSession, clientSession, CLAIMS)
                .orElseThrow();
        clientSession.setNote(AuthenticationManager.SSO_AUTH, "true");

        String grantId = AuthenticationEventSnapshotStore.persist(session,
                emptyAuthenticationSession(CLAIMS), userSession, clientSession, CLAIMS).orElseThrow();
        ClientSessionContext context = clientSessionContext(clientSession);
        AuthenticationEventSnapshotStore.attachGrant(context, grantId);
        assertEquals("pwd", AuthenticationEventSnapshotStore.grant(session, context).orElseThrow()
                .event().executions().get(0).amrIdentifier());
    }

    private static AuthenticationEvent event(String method, String time) {
        return new AuthenticationEvent(List.of(new AuthenticationMethodExecution(method, Instant.parse(time), Map.of(), Optional.empty())));
    }

    private static AuthenticationSessionModel authenticationSession(AuthenticationEvent event, String claims) {
        String serialized = AuthenticationEventSnapshotCodec.serialize(event);
        return proxy(AuthenticationSessionModel.class, (method, arguments) -> switch (method.getName()) {
            case "getAuthNote" -> AuthenticationEventSnapshotStore.AUTH_SESSION_EVENT_NOTE.equals(arguments[0]) ? serialized : null;
            case "getClientNote" -> OIDCLoginProtocol.CLAIMS_PARAM.equals(arguments[0]) ? claims : null;
            default -> defaultValue(method.getReturnType());
        });
    }

    private static AuthenticationSessionModel emptyAuthenticationSession(String claims) {
        return proxy(AuthenticationSessionModel.class, (method, arguments) -> switch (method.getName()) {
            case "getClientNote" -> OIDCLoginProtocol.CLAIMS_PARAM.equals(arguments[0]) ? claims : null;
            default -> defaultValue(method.getReturnType());
        });
    }

    private static KeycloakSession keycloakSession(Map<String, Map<String, String>> snapshots) {
        SingleUseObjectProvider store = proxy(SingleUseObjectProvider.class, (method, arguments) -> switch (method.getName()) {
            case "put" -> {
                snapshots.put((String) arguments[0], Map.copyOf((Map<String, String>) arguments[2]));
                yield null;
            }
            case "get" -> snapshots.get(arguments[0]);
            default -> defaultValue(method.getReturnType());
        });
        return proxy(KeycloakSession.class, (method, arguments) -> "singleUseObjects".equals(method.getName()) ? store : defaultValue(method.getReturnType()));
    }

    private static UserSessionModel userSession(String userId) {
        RealmModel realm = proxy(RealmModel.class, (method, arguments) -> switch (method.getName()) {
            case "getId" -> "realm";
            case "getSsoSessionMaxLifespan" -> 3600;
            case "getSsoSessionMaxLifespanRememberMe", "getClientSessionMaxLifespan", "getClientOfflineSessionMaxLifespan" -> 0;
            case "isOfflineSessionMaxLifespanEnabled" -> false;
            default -> defaultValue(method.getReturnType());
        });
        UserModel user = proxy(UserModel.class, (method, arguments) -> "getId".equals(method.getName()) ? userId : defaultValue(method.getReturnType()));
        Map<String, String> notes = new HashMap<>();
        return proxy(UserSessionModel.class, (method, arguments) -> switch (method.getName()) {
            case "getRealm" -> realm;
            case "getUser" -> user;
            case "getStarted" -> (int) (System.currentTimeMillis() / 1000);
            case "isRememberMe" -> false;
            case "getNote" -> notes.get(arguments[0]);
            case "setNote" -> {
                notes.put((String) arguments[0], (String) arguments[1]);
                yield null;
            }
            default -> defaultValue(method.getReturnType());
        });
    }

    private static AuthenticatedClientSessionModel clientSession(UserSessionModel userSession) {
        ClientModel client = proxy(ClientModel.class, (method, arguments) -> switch (method.getName()) {
            case "getId" -> "client";
            case "getAttribute" -> null;
            default -> defaultValue(method.getReturnType());
        });
        Map<String, String> notes = new HashMap<>();
        return proxy(AuthenticatedClientSessionModel.class, (method, arguments) -> switch (method.getName()) {
            case "getUserSession" -> userSession;
            case "getClient" -> client;
            case "getStarted" -> (int) (System.currentTimeMillis() / 1000);
            case "getNote" -> notes.get(arguments[0]);
            case "setNote" -> {
                notes.put((String) arguments[0], (String) arguments[1]);
                yield null;
            }
            default -> defaultValue(method.getReturnType());
        });
    }

    private static ClientSessionContext clientSessionContext(AuthenticatedClientSessionModel clientSession) {
        Map<String, Object> attributes = new HashMap<>();
        return proxy(ClientSessionContext.class, (method, arguments) -> switch (method.getName()) {
            case "getClientSession" -> clientSession;
            case "setAttribute" -> {
                attributes.put((String) arguments[0], arguments[1]);
                yield null;
            }
            case "getAttribute" -> {
                Object value = attributes.get(arguments[0]);
                yield value == null ? null : ((Class<?>) arguments[1]).cast(value);
            }
            default -> defaultValue(method.getReturnType());
        });
    }

    @SuppressWarnings("unchecked")
    private static <T> T proxy(Class<T> type, Invocation invocation) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] { type }, (proxy, method, arguments) -> {
            if ("toString".equals(method.getName())) {
                return type.getSimpleName();
            }
            return invocation.call(method, arguments == null ? new Object[0] : arguments);
        });
    }

    private static Object defaultValue(Class<?> type) {
        if (!type.isPrimitive()) {
            return null;
        }
        if (boolean.class.equals(type)) {
            return false;
        }
        if (int.class.equals(type)) {
            return 0;
        }
        if (long.class.equals(type)) {
            return 0L;
        }
        if (double.class.equals(type)) {
            return 0D;
        }
        if (float.class.equals(type)) {
            return 0F;
        }
        if (short.class.equals(type)) {
            return (short) 0;
        }
        if (byte.class.equals(type)) {
            return (byte) 0;
        }
        if (char.class.equals(type)) {
            return (char) 0;
        }
        return null;
    }

    @FunctionalInterface
    private interface Invocation {
        Object call(java.lang.reflect.Method method, Object[] arguments) throws Throwable;
    }
}
