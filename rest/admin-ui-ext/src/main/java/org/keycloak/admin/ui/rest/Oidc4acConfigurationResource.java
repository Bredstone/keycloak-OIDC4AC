/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package org.keycloak.admin.ui.rest;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;

import org.keycloak.admin.ui.rest.model.Oidc4acConfigurationRepresentation;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc4ac.disclosure.OIDC4ACDisclosurePolicy;
import org.keycloak.protocol.oidc4ac.OIDC4ACRealmSettings;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;

/**
 * Small, purpose-built Admin Console surface for configuring OIDC4AC without
 * requiring administrators to understand execution internals.
 */
public final class Oidc4acConfigurationResource {

    private static final String PLANNER_PROVIDER = "oidc4ac-factor-planner";
    private static final String FACTOR_FLOW_ALIAS = "factor_flow_alias";
    private final RealmModel realm;
    private final AdminPermissionEvaluator auth;

    public Oidc4acConfigurationResource(KeycloakSession session, RealmModel realm, AdminPermissionEvaluator auth) {
        this.realm = realm;
        this.auth = auth;
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Oidc4acConfigurationRepresentation get(@QueryParam("clientId") String clientId) {
        auth.realm().requireViewRealm();
        Oidc4acConfigurationRepresentation representation = new Oidc4acConfigurationRepresentation();
        representation.setEnabled(OIDC4ACRealmSettings.isEnabled(realm));
        representation.setClientId(clientId);
        String realmPolicy = realm.getAttribute(OIDC4ACDisclosurePolicy.REALM_ALLOWED_ATTRIBUTE);
        representation.setRealmDisclosureModes(OIDC4ACDisclosurePolicy.parseModes(realmPolicy));
        if (clientId != null) {
            realm.getClientsStream().filter(client -> clientId.equals(client.getClientId())).findFirst()
                    .ifPresent(client -> {
                        String clientPolicy = client.getAttribute(OIDC4ACDisclosurePolicy.CLIENT_ALLOWED_ATTRIBUTE);
                        representation.setClientDisclosureModes(OIDC4ACDisclosurePolicy.parseModes(clientPolicy));
                    });
        }
        findPlanner().ifPresent(planner -> {
            representation.setPlannerConfigured(true);
            representation.setBrowserFlowAlias(planner.browserFlowAlias());
            representation.setFactorFlowAlias(planner.factorFlowAlias());
            representation.setPlannerExecutionId(planner.execution().getId());
            representation.setPlannerConfigId(planner.execution().getAuthenticatorConfig());
        });
        return representation;
    }

    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Oidc4acConfigurationRepresentation update(Oidc4acConfigurationRepresentation input) {
        auth.realm().requireManageRealm();
        if (input == null) {
            throw new jakarta.ws.rs.BadRequestException("OIDC4AC configuration is required");
        }
        if (input.getEnabled() != null) {
            realm.setAttribute(OIDC4ACRealmSettings.ENABLED_ATTRIBUTE, Boolean.toString(input.getEnabled()));
        }
        boolean updateRealmPolicy = !Boolean.FALSE.equals(input.getRealmPolicyUpdate());
        if (updateRealmPolicy) {
            setModes(realm, OIDC4ACDisclosurePolicy.REALM_ALLOWED_ATTRIBUTE, input.getRealmDisclosureModes());
        }

        List<String> clientIds = new ArrayList<>(input.getClientIds() == null ? List.of() : input.getClientIds());
        boolean singleClient = input.getClientId() != null && !input.getClientId().isBlank();
        boolean updateClientPolicy = Boolean.TRUE.equals(input.getClientPolicyUpdate())
                || singleClient || !clientIds.isEmpty();
        if (updateClientPolicy) {
            if (singleClient && !clientIds.contains(input.getClientId())) {
                clientIds.add(input.getClientId());
            }
            if (!singleClient) {
                // The multi-select represents the complete set of explicit overrides.
                // Removing a client therefore returns it to the realm default.
                realm.getClientsStream()
                        .filter(client -> !clientIds.contains(client.getClientId()))
                        .forEach(client -> client.removeAttribute(OIDC4ACDisclosurePolicy.CLIENT_ALLOWED_ATTRIBUTE));
            }
            if (!clientIds.isEmpty()) {
                List<org.keycloak.models.ClientModel> selectedClients = realm.getClientsStream()
                        .filter(client -> clientIds.contains(client.getClientId())).toList();
                if (selectedClients.size() != clientIds.stream().distinct().count()) {
                    throw new jakarta.ws.rs.BadRequestException("One or more selected clients do not exist");
                }
                selectedClients.forEach(client -> setModes(client,
                        OIDC4ACDisclosurePolicy.CLIENT_ALLOWED_ATTRIBUTE, input.getClientDisclosureModes()));
            }
        }

        Oidc4acConfigurationRepresentation result = get(input.getClientId());
        result.setClientIds(clientIds);
        return result;
    }

    private Optional<Planner> findPlanner() {
        AuthenticationFlowModel browserFlow = realm.getBrowserFlow();
        return browserFlow == null ? Optional.empty() : findPlanner(browserFlow, browserFlow.getAlias());
    }

    private Optional<Planner> findPlanner(AuthenticationFlowModel flow, String browserAlias) {
        List<org.keycloak.models.AuthenticationExecutionModel> executions = realm.getAuthenticationExecutionsStream(flow.getId()).toList();
        for (AuthenticationExecutionModel execution : executions) {
            if (execution.isDisabled()) {
                continue;
            }
            if (PLANNER_PROVIDER.equals(execution.getAuthenticator())) {
                String configured = execution.getAuthenticatorConfig() == null ? null
                        : Optional.ofNullable(realm.getAuthenticatorConfigById(execution.getAuthenticatorConfig()))
                                .map(config -> config.getConfig().get(FACTOR_FLOW_ALIAS)).orElse(null);
                return Optional.of(new Planner(execution, browserAlias, configured));
            }
            if (execution.isAuthenticatorFlow()) {
                AuthenticationFlowModel child = realm.getAuthenticationFlowById(execution.getFlowId());
                if (child != null) {
                    Optional<Planner> nested = findPlanner(child, browserAlias);
                    if (nested.isPresent()) {
                        return nested;
                    }
                }
            }
        }
        return Optional.empty();
    }

    private static void setModes(RealmModel realm, String name, Map<String, String> fieldModes) {
        if (fieldModes == null || fieldModes.isEmpty()) {
            realm.removeAttribute(name);
        } else {
            realm.setAttribute(name, OIDC4ACDisclosurePolicy.serializeModes(validateFieldModes(fieldModes)));
        }
    }

    private static void setModes(org.keycloak.models.ClientModel client, String name, Map<String, String> fieldModes) {
        if (fieldModes == null || fieldModes.isEmpty()) {
            client.removeAttribute(name);
        } else {
            client.setAttribute(name, OIDC4ACDisclosurePolicy.serializeModes(validateFieldModes(fieldModes)));
        }
    }

    private static Map<String, String> validateFieldModes(Map<String, String> fieldModes) {
        if (fieldModes == null) {
            return Map.of();
        }
        fieldModes.forEach((path, fieldMode) -> {
            if (path == null || path.isBlank()) {
                throw new jakarta.ws.rs.BadRequestException("OIDC4AC disclosure field paths cannot be blank");
            }
            if (!OIDC4ACDisclosurePolicy.MODE_DEFAULT.equals(fieldMode)
                    && !OIDC4ACDisclosurePolicy.MODE_REQUESTED.equals(fieldMode)
                    && !OIDC4ACDisclosurePolicy.MODE_NEVER.equals(fieldMode)) {
                throw new jakarta.ws.rs.BadRequestException("Unknown OIDC4AC field disclosure mode: " + fieldMode);
            }
        });
        return fieldModes;
    }


    private record Planner(org.keycloak.models.AuthenticationExecutionModel execution, String browserFlowAlias,
            String factorFlowAlias) {
    }
}
