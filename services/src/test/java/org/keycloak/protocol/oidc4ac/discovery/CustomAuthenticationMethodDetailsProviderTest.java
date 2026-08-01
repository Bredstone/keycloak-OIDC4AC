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
package org.keycloak.protocol.oidc4ac.discovery;

import java.lang.reflect.Proxy;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.representations.OIDCConfigurationRepresentation;
import org.keycloak.protocol.oidc4ac.spi.AuthenticationMethodCapability;
import org.keycloak.protocol.oidc4ac.spi.AuthenticationMethodDetails;
import org.keycloak.protocol.oidc4ac.spi.AuthenticationMethodDetailsContext;
import org.keycloak.protocol.oidc4ac.spi.AuthenticationMethodDetailsProvider;
import org.keycloak.sessions.AuthenticationSessionModel;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/** Verifies the extension contract with an external-style email adapter. */
public class CustomAuthenticationMethodDetailsProviderTest {

    @Test
    public void customProviderContributesDiscoveryAndASecretFreeEventDescription() {
        AuthenticationMethodDetailsProvider provider = new EmailCodeProvider();
        AuthenticationMethodDetailsContext context = new AuthenticationMethodDetailsContext(
                proxy(KeycloakSession.class), proxy(RealmModel.class), proxy(UserModel.class),
                proxy(AuthenticationSessionModel.class), null, "custom-email-authenticator", "email-execution", "email", null,
                Instant.parse("2026-07-29T20:00:00Z"));

        assertTrue(provider.supports(context));
        AuthenticationMethodDetails details = provider.describeSuccessfulExecution(context).orElseThrow();
        assertEquals("email", details.amrIdentifier());
        assertEquals("email", details.metadata().get("channel"));
        assertEquals("urn:example:oidc4ac:email", details.metadata().get("trust_framework"));
        assertEquals("aal2", details.metadata().get("assurance_level"));
        assertEquals("code", details.properties().orElseThrow().get("email_verification_method"));

        OIDCConfigurationRepresentation configuration = new OIDCConfigurationRepresentation();
        configuration.setClaimsSupported(List.of("sub"));
        OIDC4ACDiscoveryMetadata.apply(configuration, provider.getCapabilities());
        assertEquals(List.of("email"), configuration.getOtherClaims().get("amr_identifiers_supported"));
        assertEquals(List.of("email_verification_method"),
                configuration.getOtherClaims().get("email_properties_supported"));
        assertEquals(List.of("assurance_level", "channel", "trust_framework"),
                configuration.getOtherClaims().get("email_metadata_supported"));
        assertEquals(List.of("code"), configuration.getOtherClaims().get("email_verification_method_values_supported"));
    }

    private static final class EmailCodeProvider implements AuthenticationMethodDetailsProvider {
        @Override
        public java.util.Collection<AuthenticationMethodCapability> getCapabilities() {
            return List.of(new AuthenticationMethodCapability("email", Set.of("email_verification_method"),
                    Set.of("channel", "trust_framework", "assurance_level"),
                    Map.of("email_verification_method", Set.of("code"))));
        }

        @Override
        public boolean supports(AuthenticationMethodDetailsContext context) {
            return "custom-email-authenticator".equals(context.authenticatorProviderId());
        }

        @Override
        public Optional<AuthenticationMethodDetails> describeSuccessfulExecution(AuthenticationMethodDetailsContext context) {
            return Optional.of(new AuthenticationMethodDetails("email", context.executionTime(),
                    Map.of("channel", "email", "trust_framework", "urn:example:oidc4ac:email", "assurance_level", "aal2"),
                    Optional.of(Map.of("email_verification_method", "code"))));
        }

        @Override
        public void close() {
        }
    }

    @SuppressWarnings("unchecked")
    private static <T> T proxy(Class<T> type) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] { type }, (proxy, method, arguments) -> null);
    }
}
