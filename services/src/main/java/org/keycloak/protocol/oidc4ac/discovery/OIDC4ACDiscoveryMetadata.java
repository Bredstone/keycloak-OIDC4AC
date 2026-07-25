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

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.jboss.logging.Logger;
import org.keycloak.common.Profile;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.representations.OIDCConfigurationRepresentation;
import org.keycloak.protocol.oidc4ac.OIDC4ACConstants;
import org.keycloak.protocol.oidc4ac.spi.AuthenticationMethodCapability;
import org.keycloak.protocol.oidc4ac.spi.AuthenticationMethodDetailsProvider;

/** Adds capability-derived OIDC4AC metadata only while the experimental feature is enabled. */
public final class OIDC4ACDiscoveryMetadata {

    private static final Logger LOG = Logger.getLogger(OIDC4ACDiscoveryMetadata.class);
    private static final String IDENTIFIERS_SUPPORTED = "amr_identifiers_supported";
    private static final String REQUEST_SUPPORTED = "amr_details_request_supported";

    private OIDC4ACDiscoveryMetadata() {
    }

    public static void apply(OIDCConfigurationRepresentation configuration, KeycloakSession session) {
        if (!Profile.isFeatureEnabled(Profile.Feature.OIDC4AC)) {
            return;
        }

        List<AuthenticationMethodCapability> capabilities = new ArrayList<>();
        for (AuthenticationMethodDetailsProvider provider : session.getAllProviders(AuthenticationMethodDetailsProvider.class)) {
            try {
                capabilities.addAll(provider.getCapabilities());
            } catch (RuntimeException e) {
                // Discovery must remain available if an optional capability provider fails.
                LOG.warn("An OIDC4AC authentication-method-details provider failed while producing discovery metadata");
            }
        }
        apply(configuration, capabilities);
    }

    static void apply(OIDCConfigurationRepresentation configuration, Collection<AuthenticationMethodCapability> capabilities) {
        LinkedHashSet<String> claims = new LinkedHashSet<>(configuration.getClaimsSupported());
        claims.add(OIDC4ACConstants.AMR_DETAILS);
        configuration.setClaimsSupported(List.copyOf(claims));
        configuration.setOtherClaims(REQUEST_SUPPORTED, true);

        Map<String, Set<String>> propertiesByIdentifier = new LinkedHashMap<>();
        Map<String, Set<String>> finiteValuesByProperty = new LinkedHashMap<>();
        for (AuthenticationMethodCapability capability : capabilities) {
            propertiesByIdentifier.computeIfAbsent(capability.amrIdentifier(), ignored -> new LinkedHashSet<>())
                    .addAll(capability.propertyNames());
            capability.finiteStringPropertyValues().forEach((property, values) -> finiteValuesByProperty
                    .computeIfAbsent(property, ignored -> new LinkedHashSet<>()).addAll(values));
        }

        configuration.setOtherClaims(IDENTIFIERS_SUPPORTED, sorted(propertiesByIdentifier.keySet()));
        propertiesByIdentifier.forEach((identifier, properties) -> configuration.setOtherClaims(
                identifier + "_properties_supported", sorted(properties)));
        // PCR-010: advertise values only for finite, closed string vocabularies.
        finiteValuesByProperty.forEach((property, values) -> configuration.setOtherClaims(
                property + "_values_supported", sorted(values)));
    }

    private static List<String> sorted(Collection<String> values) {
        return values.stream().sorted().toList();
    }
}
