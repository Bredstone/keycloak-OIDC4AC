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
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.representations.OIDCConfigurationRepresentation;
import org.keycloak.protocol.oidc4ac.OIDC4ACConstants;
import org.keycloak.protocol.oidc4ac.OIDC4ACRealmSettings;
import org.keycloak.protocol.oidc4ac.spi.AuthenticationMethodCapability;
import org.keycloak.protocol.oidc4ac.spi.AuthenticationMethodDetailsProvider;

/** Adds capability-derived OIDC4AC metadata only while the experimental feature is enabled. */
public final class OIDC4ACDiscoveryMetadata {

    private static final Logger LOG = Logger.getLogger(OIDC4ACDiscoveryMetadata.class);
    private static final String IDENTIFIERS_SUPPORTED = "amr_identifiers_supported";
    private static final String REQUEST_SUPPORTED = "amr_details_request_supported";
    private static final String PLANNER_PROVIDER = "oidc4ac-factor-planner";

    private OIDC4ACDiscoveryMetadata() {
    }

    public static void apply(OIDCConfigurationRepresentation configuration, KeycloakSession session) {
        apply(configuration, session, null);
    }

    /**
     * Applies discovery metadata and reports request-driven support only when
     * an enabled planner execution is present in the realm's active browser
     * flow. Informational disclosure remains available independently.
     */
    public static void apply(OIDCConfigurationRepresentation configuration, KeycloakSession session,
            RealmModel realm) {
        if (!Profile.isFeatureEnabled(Profile.Feature.OIDC4AC) || !OIDC4ACRealmSettings.isEnabled(realm)) {
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
        apply(configuration, capabilities, realm == null || hasEnabledPlanner(realm));
    }

    static void apply(OIDCConfigurationRepresentation configuration, Collection<AuthenticationMethodCapability> capabilities) {
        apply(configuration, capabilities, true);
    }

    static void apply(OIDCConfigurationRepresentation configuration, Collection<AuthenticationMethodCapability> capabilities,
            boolean requestModeSupported) {
        LinkedHashSet<String> claims = new LinkedHashSet<>(configuration.getClaimsSupported());
        claims.add(OIDC4ACConstants.AMR_DETAILS);
        configuration.setClaimsSupported(List.copyOf(claims));
        configuration.setOtherClaims(REQUEST_SUPPORTED, requestModeSupported);

        Map<String, Set<String>> propertiesByIdentifier = new LinkedHashMap<>();
        Map<String, Set<String>> metadataByIdentifier = new LinkedHashMap<>();
        Map<String, Set<String>> finiteValuesByProperty = new LinkedHashMap<>();
        for (AuthenticationMethodCapability capability : capabilities) {
            propertiesByIdentifier.computeIfAbsent(capability.amrIdentifier(), ignored -> new LinkedHashSet<>())
                    .addAll(capability.propertyNames());
            metadataByIdentifier.computeIfAbsent(capability.amrIdentifier(), ignored -> new LinkedHashSet<>())
                    .addAll(capability.metadataNames().stream().filter(name -> !"time".equals(name)).toList());
            capability.finiteStringPropertyValues().forEach((property, values) -> finiteValuesByProperty
                    .computeIfAbsent(property, ignored -> new LinkedHashSet<>()).addAll(values));
        }

        configuration.setOtherClaims(IDENTIFIERS_SUPPORTED, sorted(propertiesByIdentifier.keySet()));
        propertiesByIdentifier.forEach((identifier, properties) -> configuration.setOtherClaims(
                identifier + "_properties_supported", sorted(properties)));
        metadataByIdentifier.forEach((identifier, metadata) -> configuration.setOtherClaims(
                identifier + "_metadata_supported", sorted(metadata)));
        // PCR-010: advertise values only for finite, closed string vocabularies.
        finiteValuesByProperty.forEach((property, values) -> configuration.setOtherClaims(
                property + "_values_supported", sorted(values)));
    }

    static boolean hasEnabledPlanner(RealmModel realm) {
        AuthenticationFlowModel browserFlow = realm.getBrowserFlow();
        return browserFlow != null && hasEnabledPlanner(realm, browserFlow);
    }

    private static boolean hasEnabledPlanner(RealmModel realm, AuthenticationFlowModel flow) {
        return realm.getAuthenticationExecutionsStream(flow.getId()).anyMatch(execution -> {
            if (execution.isDisabled()) {
                return false;
            }
            if (PLANNER_PROVIDER.equals(execution.getAuthenticator())) {
                return true;
            }
            if (!execution.isAuthenticatorFlow()) {
                return false;
            }
            AuthenticationFlowModel child = realm.getAuthenticationFlowById(execution.getFlowId());
            return child != null && hasEnabledPlanner(realm, child);
        });
    }

    private static List<String> sorted(Collection<String> values) {
        return values.stream().sorted().toList();
    }
}
