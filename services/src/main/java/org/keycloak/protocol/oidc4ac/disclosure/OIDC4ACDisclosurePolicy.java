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
package org.keycloak.protocol.oidc4ac.disclosure;

import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;

import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc4ac.request.AllOfExpression;
import org.keycloak.protocol.oidc4ac.request.AmrDetailsClaimRequest;
import org.keycloak.protocol.oidc4ac.request.AmrDetailsClaimsRequest;
import org.keycloak.protocol.oidc4ac.request.AuthenticationMethodExpression;
import org.keycloak.protocol.oidc4ac.request.MethodExpression;
import org.keycloak.protocol.oidc4ac.request.OneOfExpression;

/**
 * Realm/client disclosure policy for optional OIDC4AC metadata and properties.
 *
 * <p>The policy is an intersection of two allow-lists stored as attributes.
 * Values are comma, whitespace, or newline separated paths such as
 * {@code amr_metadata.ip} or {@code amr_properties.otp_algorithm}. The
 * wildcard ({@code *}) permits every optional field. An unset attribute is
 * permissive. Mandatory method identifiers and execution times are never
 * governed by this policy because the complete Authentication Event requires
 * them at every delivery location.</p>
 */
public final class OIDC4ACDisclosurePolicy {

    public static final String REALM_ALLOWED_ATTRIBUTE = "oidc4ac.disclosure.allowed";
    public static final String CLIENT_ALLOWED_ATTRIBUTE = "oidc4ac.disclosure.allowed";
    public static final String WILDCARD = "*";
    /** Internal value used to persist an explicit deny-all optional-field policy. */
    public static final String DENY_ALL = "__none__";

    private final Set<String> realmAllowed;
    private final Set<String> clientAllowed;

    private OIDC4ACDisclosurePolicy(Set<String> realmAllowed, Set<String> clientAllowed) {
        this.realmAllowed = Set.copyOf(realmAllowed);
        this.clientAllowed = Set.copyOf(clientAllowed);
    }

    public static OIDC4ACDisclosurePolicy forModels(RealmModel realm, ClientModel client) {
        return new OIDC4ACDisclosurePolicy(
                parse(realm == null ? null : realm.getAttribute(REALM_ALLOWED_ATTRIBUTE)),
                parse(client == null ? null : client.getAttribute(CLIENT_ALLOWED_ATTRIBUTE)));
    }

    public static OIDC4ACDisclosurePolicy permissive() {
        return new OIDC4ACDisclosurePolicy(Set.of(WILDCARD), Set.of(WILDCARD));
    }

    public static OIDC4ACDisclosurePolicy forAttributeValues(String realmValue, String clientValue) {
        return new OIDC4ACDisclosurePolicy(parse(realmValue), parse(clientValue));
    }

    public static String serialize(Collection<String> paths) {
        if (paths == null || paths.isEmpty()) {
            return WILDCARD;
        }
        return String.join(",", paths);
    }

    /** Returns whether all locally essential optional fields can be delivered. */
    public boolean essentialRequestsRepresentable(AmrDetailsClaimsRequest requests) {
        return requests.idToken().stream().allMatch(this::essentialRequestRepresentable)
                && requests.userInfo().stream().allMatch(this::essentialRequestRepresentable);
    }

    public boolean allows(String path) {
        return allows(realmAllowed, path) && allows(clientAllowed, path);
    }

    private boolean essentialRequestRepresentable(AmrDetailsClaimRequest request) {
        return request.expression().map(this::essentialExpressionRepresentable).orElse(true);
    }

    private boolean essentialExpressionRepresentable(AuthenticationMethodExpression expression) {
        if (expression instanceof AllOfExpression allOf) {
            return allOf.children().stream().allMatch(this::essentialExpressionRepresentable);
        }
        if (expression instanceof OneOfExpression oneOf) {
            return oneOf.children().stream().anyMatch(this::essentialExpressionRepresentable);
        }
        MethodExpression method = (MethodExpression) expression;
        return method.metadata().entrySet().stream()
                .filter(entry -> entry.getValue().essential())
                .allMatch(entry -> allows("amr_metadata." + entry.getKey()))
                && method.properties().entrySet().stream()
                .filter(entry -> entry.getValue().essential())
                .allMatch(entry -> allows("amr_properties." + entry.getKey()));
    }

    private static boolean allows(Set<String> allowed, String path) {
        return allowed.contains(WILDCARD) || allowed.contains(path);
    }

    private static Set<String> parse(String value) {
        if (value == null || value.isBlank()) {
            return Set.of(WILDCARD);
        }
        if (DENY_ALL.equalsIgnoreCase(value.trim())) {
            return Set.of();
        }
        LinkedHashSet<String> paths = new LinkedHashSet<>();
        Arrays.stream(value.split("[,\\s]+"))
                .map(item -> item.trim().toLowerCase(Locale.ROOT))
                .filter(item -> !item.isBlank())
                .forEach(paths::add);
        return paths.isEmpty() ? Set.of(WILDCARD) : paths;
    }
}
