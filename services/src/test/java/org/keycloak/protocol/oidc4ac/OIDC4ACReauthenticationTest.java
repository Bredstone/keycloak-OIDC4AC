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
package org.keycloak.protocol.oidc4ac;

import java.lang.reflect.Proxy;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.keycloak.common.Profile;
import org.keycloak.common.profile.CommaSeparatedListProfileConfigResolver;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc4ac.event.AuthenticationEventSnapshotCodec;
import org.keycloak.protocol.oidc4ac.event.AuthenticationEventSnapshotStore;
import org.keycloak.protocol.oidc4ac.model.AuthenticationEvent;
import org.keycloak.protocol.oidc4ac.model.AuthenticationMethodExecution;
import org.keycloak.sessions.AuthenticationSessionModel;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class OIDC4ACReauthenticationTest {

    @Before
    public void enableFeature() {
        Profile.configure(new CommaSeparatedListProfileConfigResolver(Profile.Feature.OIDC4AC.getVersionedKey(), ""));
    }

    @After
    public void resetFeature() {
        Profile.reset();
    }

    @Test
    public void doesNotReauthenticateWhenTheSsoSnapshotMatchesButRetriesWhenItDoesNot() {
        UserSessionModel passwordSso = userSession(AuthenticationEventSnapshotCodec.serialize(new AuthenticationEvent(List.of(
                new AuthenticationMethodExecution("pwd", Instant.parse("2026-07-25T12:00:00Z"), Map.of(), Optional.empty())))));
        OIDCLoginProtocol protocol = new OIDCLoginProtocol(null, null, null, null, null);

        assertFalse(protocol.requireReauthentication(passwordSso, authenticationSession("""
                {"id_token":{"amr_details":{"essential":true,"amr_identifier":{"value":"pwd"},"amr_metadata":{"time":null}}}}
                """)));
        assertTrue(protocol.requireReauthentication(passwordSso, authenticationSession("""
                {"id_token":{"amr_details":{"essential":true,"amr_identifier":{"value":"otp"},"amr_metadata":{"time":null}}}}
                """)));
    }

    private static AuthenticationSessionModel authenticationSession(String claims) {
        return proxy(AuthenticationSessionModel.class, Map.of(OIDCLoginProtocol.CLAIMS_PARAM, claims));
    }

    private static UserSessionModel userSession(String snapshot) {
        return proxy(UserSessionModel.class, Map.of(AuthenticationEventSnapshotStore.USER_SESSION_SSO_EVENT_NOTE, snapshot));
    }

    @SuppressWarnings("unchecked")
    private static <T> T proxy(Class<T> type, Map<String, String> notes) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] { type }, (proxy, method, arguments) -> {
            if ("getClientNote".equals(method.getName()) || "getNote".equals(method.getName())) {
                return notes.get(arguments[0]);
            }
            if ("toString".equals(method.getName())) {
                return type.getSimpleName();
            }
            throw new UnsupportedOperationException(method.getName());
        });
    }
}
