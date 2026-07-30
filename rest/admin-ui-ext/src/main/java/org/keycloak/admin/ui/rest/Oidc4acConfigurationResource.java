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
    private static final String MODE_ALL = "all";
    private static final String MODE_SELECTED = "selected";
    private static final String MODE_NONE = "none";
    private static final String MODE_INHERIT = "inherit";

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
        representation.setRealmDisclosureMode(mode(realmPolicy, MODE_ALL));
        representation.setRealmAllowedFields(split(realmPolicy));
        if (clientId != null) {
            realm.getClientsStream().filter(client -> clientId.equals(client.getClientId())).findFirst()
                    .ifPresent(client -> {
                        String clientPolicy = client.getAttribute(OIDC4ACDisclosurePolicy.CLIENT_ALLOWED_ATTRIBUTE);
                        representation.setClientDisclosureMode(mode(clientPolicy, MODE_INHERIT));
                        representation.setClientAllowedFields(split(clientPolicy));
                    });
        } else {
            Map<String, List<String>> clientPolicies = new java.util.LinkedHashMap<>();
            realm.getClientsStream().forEach(client -> {
                String policy = client.getAttribute(OIDC4ACDisclosurePolicy.CLIENT_ALLOWED_ATTRIBUTE);
                if (policy != null && !policy.isBlank()) {
                    clientPolicies.put(client.getClientId(), split(policy));
                }
            });
            representation.setClientAllowedFieldsByClient(clientPolicies);
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
        String realmMode = mode(realm.getAttribute(OIDC4ACDisclosurePolicy.REALM_ALLOWED_ATTRIBUTE), MODE_ALL);
        if (updateRealmPolicy) {
            realmMode = normalizeRealmMode(input);
            setAttribute(realm, OIDC4ACDisclosurePolicy.REALM_ALLOWED_ATTRIBUTE, realmMode,
                    input.getRealmAllowedFields());
        }

        List<String> clientIds = new ArrayList<>(input.getClientIds() == null ? List.of() : input.getClientIds());
        boolean legacySingleClient = clientIds.isEmpty() && input.getClientId() != null && !input.getClientId().isBlank();
        boolean updateClientPolicy = Boolean.TRUE.equals(input.getClientPolicyUpdate())
                || legacySingleClient || !clientIds.isEmpty() || input.getClientDisclosureMode() != null;
        if (updateClientPolicy) {
            if (legacySingleClient) {
                clientIds.add(input.getClientId());
            }
            if (!legacySingleClient && clientIds.isEmpty() && input.getClientDisclosureMode() != null
                    && !MODE_INHERIT.equals(input.getClientDisclosureMode())) {
                throw new jakarta.ws.rs.BadRequestException("Select at least one client for a client disclosure override");
            }
            if (!legacySingleClient) {
                // The multi-select represents the complete set of explicit overrides.
                // Removing a client therefore returns it to the realm default.
                realm.getClientsStream()
                        .filter(client -> !clientIds.contains(client.getClientId()))
                        .forEach(client -> client.removeAttribute(OIDC4ACDisclosurePolicy.CLIENT_ALLOWED_ATTRIBUTE));
            }
            if (!clientIds.isEmpty()) {
                String clientMode = normalizeClientMode(input, clientIds);
                List<org.keycloak.models.ClientModel> selectedClients = realm.getClientsStream()
                        .filter(client -> clientIds.contains(client.getClientId())).toList();
                if (selectedClients.size() != clientIds.stream().distinct().count()) {
                    throw new jakarta.ws.rs.BadRequestException("One or more selected clients do not exist");
                }
                selectedClients.forEach(client -> setAttribute(client, OIDC4ACDisclosurePolicy.CLIENT_ALLOWED_ATTRIBUTE,
                        clientMode, input.getClientAllowedFields()));
                input.setClientDisclosureMode(clientMode);
            }
        }

        Oidc4acConfigurationRepresentation result = get(input.getClientId());
        result.setRealmDisclosureMode(realmMode);
        result.setClientDisclosureMode(input.getClientDisclosureMode());
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

    private static void setAttribute(RealmModel realm, String name, String mode, List<String> fields) {
        if (MODE_ALL.equals(mode) || MODE_INHERIT.equals(mode) || mode == null) {
            realm.removeAttribute(name);
        } else if (MODE_NONE.equals(mode)) {
            realm.setAttribute(name, OIDC4ACDisclosurePolicy.DENY_ALL);
        } else {
            realm.setAttribute(name, fields == null || fields.isEmpty()
                    ? OIDC4ACDisclosurePolicy.DENY_ALL : OIDC4ACDisclosurePolicy.serialize(fields));
        }
    }

    private static void setAttribute(org.keycloak.models.ClientModel client, String name, String mode, List<String> fields) {
        if (MODE_ALL.equals(mode) || MODE_INHERIT.equals(mode) || mode == null) {
            client.removeAttribute(name);
        } else if (MODE_NONE.equals(mode)) {
            client.setAttribute(name, OIDC4ACDisclosurePolicy.DENY_ALL);
        } else {
            client.setAttribute(name, fields == null || fields.isEmpty()
                    ? OIDC4ACDisclosurePolicy.DENY_ALL : OIDC4ACDisclosurePolicy.serialize(fields));
        }
    }

    private static String normalizeRealmMode(Oidc4acConfigurationRepresentation input) {
        if (input.getRealmDisclosureMode() == null || input.getRealmDisclosureMode().isBlank()) {
            return input.getRealmAllowedFields() == null || input.getRealmAllowedFields().isEmpty() ? MODE_ALL : MODE_SELECTED;
        }
        return validateMode(input.getRealmDisclosureMode(), false);
    }

    private static String normalizeClientMode(Oidc4acConfigurationRepresentation input, List<String> clientIds) {
        if (input.getClientDisclosureMode() == null || input.getClientDisclosureMode().isBlank()) {
            return input.getClientAllowedFields() == null || input.getClientAllowedFields().isEmpty() ? MODE_ALL : MODE_SELECTED;
        }
        return validateMode(input.getClientDisclosureMode(), true);
    }

    private static String validateMode(String mode, boolean client) {
        if (MODE_ALL.equals(mode) || MODE_SELECTED.equals(mode) || MODE_NONE.equals(mode)
                || (client && MODE_INHERIT.equals(mode))) {
            return mode;
        }
        throw new jakarta.ws.rs.BadRequestException("Unknown OIDC4AC disclosure policy mode: " + mode);
    }

    private static String mode(String value, String absentMode) {
        if (value == null || value.isBlank()) {
            return absentMode;
        }
        return OIDC4ACDisclosurePolicy.DENY_ALL.equalsIgnoreCase(value.trim()) ? MODE_NONE : MODE_SELECTED;
    }

    private static List<String> split(String value) {
        if (value == null || value.isBlank()) {
            return List.of();
        }
        if (OIDC4ACDisclosurePolicy.DENY_ALL.equalsIgnoreCase(value.trim())) {
            return List.of();
        }
        List<String> result = new ArrayList<>();
        for (String item : value.split("[,\\s]+")) {
            if (!item.isBlank()) {
                result.add(item);
            }
        }
        return result;
    }

    private record Planner(org.keycloak.models.AuthenticationExecutionModel execution, String browserFlowAlias,
            String factorFlowAlias) {
    }
}
