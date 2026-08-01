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
package org.keycloak.protocol.oidc4ac.error;

import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;

import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.AuthenticationFlowException;
import org.keycloak.common.Profile;
import org.keycloak.common.profile.CommaSeparatedListProfileConfigResolver;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.sessions.AuthenticationSessionModel;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class OIDC4ACAuthenticationFailureBridgeTest {

    @Before
    public void enableFeature() {
        Profile.configure(new CommaSeparatedListProfileConfigResolver(Profile.Feature.OIDC4AC.getVersionedKey(), ""));
    }

    @After
    public void resetFeature() {
        Profile.reset();
    }

    @Test
    public void bridgesTerminalMethodFailuresButNotEndUserRefusal() {
        AuthenticationSessionModel session = authenticationSession("""
                {"id_token":{"amr_details":{"essential":true,"amr_identifier":{"value":"otp"},"amr_metadata":{"time":null}}}}
                """);

        assertTrue(OIDC4ACAuthenticationFailureBridge.isApplicable(session,
                new AuthenticationFlowException(AuthenticationFlowError.CREDENTIAL_SETUP_REQUIRED)));
        assertFalse(OIDC4ACAuthenticationFailureBridge.isApplicable(session,
                new AuthenticationFlowException(AuthenticationFlowError.ACCESS_DENIED)));
    }

    @Test
    public void doesNotBridgeVoluntaryRequests() {
        AuthenticationSessionModel session = authenticationSession("""
                {"id_token":{"amr_details":{"amr_identifier":{"value":"otp"},"amr_metadata":{"time":null}}}}
                """);

        assertFalse(OIDC4ACAuthenticationFailureBridge.isApplicable(session,
                new AuthenticationFlowException(AuthenticationFlowError.CREDENTIAL_SETUP_REQUIRED)));
    }

    @Test
    public void bridgesAPlannedGenericFailureWrappedByTheBrowserFlow() {
        AuthenticationSessionModel session = authenticationSession("""
                {"id_token":{"amr_details":{"essential":true,"amr_identifier":{"value":"face"},"amr_metadata":{"time":null}}}}
                """);

        assertTrue(OIDC4ACAuthenticationFailureBridge.isApplicable(session,
                new AuthenticationFlowException(java.util.List.of(
                        new AuthenticationFlowException(AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR)))));
    }

    @Test
    public void bridgesUnknownUserWhenAnEssentialFactorPlanCouldNotEstablishAUser() {
        AuthenticationSessionModel session = authenticationSession("""
                {"id_token":{"amr_details":{"essential":true,"amr_identifier":{"value":"face"},"amr_metadata":{"time":null}}}}
                """);

        assertTrue(OIDC4ACAuthenticationFailureBridge.isApplicable(session,
                new AuthenticationFlowException(AuthenticationFlowError.UNKNOWN_USER)));
    }

    @Test
    public void bridgesPlannerMarkedRequirementWhenAnAlternativeFlowDiscardsFailures() {
        AuthenticationSessionModel session = authenticationSession("""
                {"id_token":{"amr_details":{"essential":true,"amr_identifier":{"value":"face"},"amr_metadata":{"time":null}}}}
                """);
        OIDC4ACAuthenticationFailureBridge.markUnmetAuthenticationRequirement(session);

        assertTrue(OIDC4ACAuthenticationFailureBridge.isApplicable(session,
                new AuthenticationFlowException(java.util.List.of())));
    }

    private static AuthenticationSessionModel authenticationSession(String claims) {
        Map<String, String> clientNotes = Map.of(OIDCLoginProtocol.CLAIMS_PARAM, claims);
        Map<String, String> authNotes = new HashMap<>();
        return (AuthenticationSessionModel) Proxy.newProxyInstance(AuthenticationSessionModel.class.getClassLoader(),
                new Class<?>[] { AuthenticationSessionModel.class }, (proxy, method, arguments) -> {
                    if ("getProtocol".equals(method.getName())) {
                        return OIDCLoginProtocol.LOGIN_PROTOCOL;
                    }
                    if ("getClientNote".equals(method.getName())) {
                        return clientNotes.get(arguments[0]);
                    }
                    if ("getAuthNote".equals(method.getName())) {
                        return authNotes.get(arguments[0]);
                    }
                    if ("setAuthNote".equals(method.getName())) {
                        authNotes.put((String) arguments[0], (String) arguments[1]);
                        return null;
                    }
                    if ("toString".equals(method.getName())) {
                        return "OIDC4AC test authentication session";
                    }
                    throw new UnsupportedOperationException(method.getName());
                });
    }
}
