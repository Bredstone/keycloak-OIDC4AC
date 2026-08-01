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
package org.keycloak.protocol.oidc4ac.providers;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.time.Instant;
import java.util.Map;
import java.util.Set;

import org.keycloak.authentication.authenticators.browser.OTPFormAuthenticatorFactory;
import org.keycloak.authentication.authenticators.browser.WebAuthnAuthenticatorFactory;
import org.keycloak.common.ClientConnection;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.credential.WebAuthnCredentialModel;
import org.keycloak.protocol.oidc4ac.spi.AuthenticationMethodDetailsContext;
import org.keycloak.sessions.AuthenticationSessionModel;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class NativeAuthenticationMethodDetailsProviderTest {

    @Test
    public void mapsVerifiedWebAuthnOnlyToPopWithoutIdentifiersOrProtectionClaims() {
        NativeAuthenticationMethodDetailsProvider provider = new NativeAuthenticationMethodDetailsProvider();
        AuthenticationMethodDetailsContext context = context(WebAuthnAuthenticatorFactory.PROVIDER_ID,
                WebAuthnCredentialModel.TYPE_TWOFACTOR);

        assertTrue(provider.supports(context));
        var details = provider.describeSuccessfulExecution(context).orElseThrow();
        assertEquals("pop", details.amrIdentifier());
        assertTrue(details.metadata().isEmpty());
        assertFalse(details.properties().isPresent());
    }

    @Test
    public void representsNetworkOriginAsStructuredLocationObject() {
        NativeAuthenticationMethodDetailsProvider provider = new NativeAuthenticationMethodDetailsProvider();
        AuthenticationMethodDetailsContext context = contextWithRemoteAddress(WebAuthnAuthenticatorFactory.PROVIDER_ID,
                WebAuthnCredentialModel.TYPE_TWOFACTOR, "203.0.113.7");

        Object location = provider.describeSuccessfulExecution(context).orElseThrow().metadata().get("location");

        assertTrue(location instanceof Map<?, ?>);
        assertEquals(Map.of("ip_address", "203.0.113.7"), location);
    }

    @Test
    public void omitsAnUnavailableOrInvalidNetworkOrigin() {
        NativeAuthenticationMethodDetailsProvider provider = new NativeAuthenticationMethodDetailsProvider();
        AuthenticationMethodDetailsContext context = contextWithRemoteAddress(WebAuthnAuthenticatorFactory.PROVIDER_ID,
                WebAuthnCredentialModel.TYPE_TWOFACTOR, "not-an-ip-address");

        assertFalse(provider.describeSuccessfulExecution(context).orElseThrow().metadata().containsKey("location"));
    }

    @Test
    public void mapsOtpWithoutGuessingCredentialSpecificProperties() {
        NativeAuthenticationMethodDetailsProvider provider = new NativeAuthenticationMethodDetailsProvider();
        AuthenticationMethodDetailsContext context = context(OTPFormAuthenticatorFactory.PROVIDER_ID, OTPCredentialModel.TYPE);

        assertTrue(provider.supports(context));
        var details = provider.describeSuccessfulExecution(context).orElseThrow();
        assertEquals("otp", details.amrIdentifier());
        assertFalse(details.properties().isPresent());
    }

    @Test
    public void mapsOnlySafePropertiesOfTheSelectedVerifiedTotpCredential() {
        NativeAuthenticationMethodDetailsProvider provider = new NativeAuthenticationMethodDetailsProvider();
        OTPCredentialModel credential = OTPCredentialModel.createTOTP("not-disclosed", 8, 30, "HmacSHA1");
        credential.setId("selected-otp");
        AuthenticationMethodDetailsContext context = context(OTPFormAuthenticatorFactory.PROVIDER_ID,
                OTPCredentialModel.TYPE, "selected-otp", credential);

        Map<String, Object> properties = provider.describeSuccessfulExecution(context).orElseThrow().properties().orElseThrow();

        assertEquals(8, properties.get("otp_length"));
        assertEquals("TOTP", properties.get("otp_algorithm"));
        assertEquals("numeric", properties.get("otp_format"));
        assertEquals("app", properties.get("otp_delivery_method"));
        assertEquals(30, properties.get("otp_time_to_live"));
        assertFalse(properties.containsKey("counter"));
        assertFalse(properties.containsKey("secret"));
    }

    @Test
    public void omitsTimeToLiveForTheSelectedHotpCredential() {
        NativeAuthenticationMethodDetailsProvider provider = new NativeAuthenticationMethodDetailsProvider();
        OTPCredentialModel credential = OTPCredentialModel.createHOTP("not-disclosed", 6, 7, "HmacSHA1");
        credential.setId("selected-otp");
        AuthenticationMethodDetailsContext context = context(OTPFormAuthenticatorFactory.PROVIDER_ID,
                OTPCredentialModel.TYPE, "selected-otp", credential);

        Map<String, Object> properties = provider.describeSuccessfulExecution(context).orElseThrow().properties().orElseThrow();

        assertEquals("HOTP", properties.get("otp_algorithm"));
        assertFalse(properties.containsKey("otp_time_to_live"));
        assertFalse(properties.containsKey("counter"));
    }

    @Test
    public void advertisesOnlySafeNativeCapabilities() {
        NativeAuthenticationMethodDetailsProvider provider = new NativeAuthenticationMethodDetailsProvider();
        assertEquals(Set.of("pwd", "otp", "pop"), provider.getCapabilities().stream()
                .map(capability -> capability.amrIdentifier()).collect(java.util.stream.Collectors.toSet()));
        assertEquals(Set.of("pwd_derivation_algorithm", "pwd_iterations", "pwd_last_updated_at"), provider.getCapabilities().stream()
                .filter(capability -> capability.amrIdentifier().equals("pwd")).findFirst().orElseThrow().propertyNames());
        assertEquals(Set.of("iss", "location"), provider.getCapabilities().stream()
                .filter(capability -> capability.amrIdentifier().equals("pwd")).findFirst().orElseThrow().metadataNames());
        assertEquals(Set.of("ip_address"), provider.getCapabilities().stream()
                .filter(capability -> capability.amrIdentifier().equals("pwd")).findFirst().orElseThrow()
                .locationTypesSupported());
        assertEquals(Set.of("otp_algorithm", "otp_delivery_method", "otp_format", "otp_length", "otp_time_to_live"),
                provider.getCapabilities().stream().filter(capability -> capability.amrIdentifier().equals("otp"))
                        .findFirst().orElseThrow().propertyNames());
        assertEquals(Set.of("HOTP", "TOTP"), provider.getCapabilities().stream()
                .filter(capability -> capability.amrIdentifier().equals("otp")).findFirst().orElseThrow()
                .finiteStringPropertyValues().get("otp_algorithm"));
    }

    private static AuthenticationMethodDetailsContext context(String execution, String credentialType) {
        return context(execution, credentialType, null, null);
    }

    private static AuthenticationMethodDetailsContext context(String execution, String credentialType, String selectedCredentialId,
            CredentialModel credential) {
        return new AuthenticationMethodDetailsContext(proxy(KeycloakSession.class), proxy(RealmModel.class), user(credential),
                proxy(AuthenticationSessionModel.class), null, execution, "execution", credentialType, selectedCredentialId,
                Instant.parse("2026-07-25T12:00:00Z"));
    }

    private static AuthenticationMethodDetailsContext contextWithRemoteAddress(String execution, String credentialType,
            String remoteAddress) {
        ClientConnection connection = proxy(ClientConnection.class, (proxy, method, arguments) -> {
            if ("getRemoteAddr".equals(method.getName())) {
                return remoteAddress;
            }
            throw new UnsupportedOperationException(method.getName());
        });
        KeycloakContext keycloakContext = proxy(KeycloakContext.class, (proxy, method, arguments) -> {
            if ("getConnection".equals(method.getName())) {
                return connection;
            }
            throw new UnsupportedOperationException(method.getName());
        });
        KeycloakSession session = proxy(KeycloakSession.class, (proxy, method, arguments) -> {
            if ("getContext".equals(method.getName())) {
                return keycloakContext;
            }
            throw new UnsupportedOperationException(method.getName());
        });
        return new AuthenticationMethodDetailsContext(session, proxy(RealmModel.class), user(null),
                proxy(AuthenticationSessionModel.class), null, execution, "execution", credentialType, null,
                Instant.parse("2026-07-25T12:00:00Z"));
    }

    private static UserModel user(CredentialModel credential) {
        SubjectCredentialManager credentialManager = proxy(SubjectCredentialManager.class, (proxy, method, arguments) -> {
            if ("getStoredCredentialById".equals(method.getName())) {
                return credential;
            }
            throw new UnsupportedOperationException(method.getName());
        });
        return proxy(UserModel.class, (proxy, method, arguments) -> {
            if ("credentialManager".equals(method.getName())) {
                return credentialManager;
            }
            throw new UnsupportedOperationException(method.getName());
        });
    }

    @SuppressWarnings("unchecked")
    private static <T> T proxy(Class<T> type) {
        return proxy(type, (proxy, method, arguments) -> {
            if ("toString".equals(method.getName())) {
                return type.getSimpleName();
            }
            throw new UnsupportedOperationException(method.getName());
        });
    }

    @SuppressWarnings("unchecked")
    private static <T> T proxy(Class<T> type, InvocationHandler handler) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] { type }, handler);
    }
}
