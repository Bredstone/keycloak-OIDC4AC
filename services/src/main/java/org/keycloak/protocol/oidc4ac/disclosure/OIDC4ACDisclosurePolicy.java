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
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.StringJoiner;

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
 * <p>The policy is an intersection of realm and client scopes stored as
 * attributes. Values are comma, whitespace, or newline separated paths such
 * as {@code amr_metadata.ip} or {@code amr_properties.otp_algorithm}. Existing
 * unprefixed stored entries are read as {@code default:path} during migration;
 * the Admin Console writes explicit {@code default:path},
 * {@code requested:path}, and {@code never:path} entries.
 * The wildcard ({@code *}) permits every optional field. An unset attribute is
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
    public static final String MODE_DEFAULT = "default";
    public static final String MODE_REQUESTED = "requested";
    public static final String MODE_NEVER = "never";
    public static final String MODE_FIELDS = "fields";

    private final PolicyScope realmPolicy;
    private final PolicyScope clientPolicy;

    private OIDC4ACDisclosurePolicy(PolicyScope realmPolicy, PolicyScope clientPolicy) {
        this.realmPolicy = realmPolicy;
        this.clientPolicy = clientPolicy;
    }

    public static OIDC4ACDisclosurePolicy forModels(RealmModel realm, ClientModel client) {
        return new OIDC4ACDisclosurePolicy(
                parse(realm == null ? null : realm.getAttribute(REALM_ALLOWED_ATTRIBUTE)),
                parse(client == null ? null : client.getAttribute(CLIENT_ALLOWED_ATTRIBUTE)));
    }

    public static OIDC4ACDisclosurePolicy permissive() {
        return new OIDC4ACDisclosurePolicy(PolicyScope.permissive(), PolicyScope.permissive());
    }

    public static OIDC4ACDisclosurePolicy forAttributeValues(String realmValue, String clientValue) {
        return new OIDC4ACDisclosurePolicy(parse(realmValue), parse(clientValue));
    }

    /** Serializes the explicit per-field disclosure modes used by the Admin Console. */
    public static String serializeModes(Map<String, String> modes) {
        if (modes == null || modes.isEmpty()) {
            return DENY_ALL;
        }
        StringJoiner result = new StringJoiner(",");
        modes.forEach((path, mode) -> {
            if (path != null && !path.isBlank() && mode != null && !mode.isBlank()) {
                result.add(mode + ":" + path);
            }
        });
        return result.length() == 0 ? DENY_ALL : result.toString();
    }

    /** Parses explicit per-field modes, also interpreting legacy allow-list entries as defaults. */
    public static Map<String, String> parseModes(String value) {
        PolicyScope scope = parse(value);
        Map<String, String> modes = new LinkedHashMap<>();
        scope.modes().forEach((path, mode) -> modes.put(path, mode.name().toLowerCase(Locale.ROOT)));
        return modes;
    }

    /** Returns whether all locally essential optional fields can be delivered. */
    public boolean essentialRequestsRepresentable(AmrDetailsClaimsRequest requests) {
        return requests.idToken().stream().allMatch(this::essentialRequestRepresentable)
                && requests.userInfo().stream().allMatch(this::essentialRequestRepresentable);
    }

    public boolean allows(String path) {
        return mode(path) != DisclosureMode.NEVER;
    }

    /** Returns whether an optional field is included when the request has no expression. */
    public boolean allowsByDefault(String path) {
        return mode(path) == DisclosureMode.DEFAULT;
    }

    public DisclosureMode mode(String path) {
        return mostRestrictive(realmPolicy.mode(path), clientPolicy.mode(path));
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
                // amr_metadata.time is mandatory for every preserved
                // execution and is therefore never subject to disclosure
                // policy, even when a stored policy lists only optional
                // fields.
                .filter(entry -> !"time".equals(entry.getKey()))
                .allMatch(entry -> allows("amr_metadata." + entry.getKey()))
                && method.properties().entrySet().stream()
                .filter(entry -> entry.getValue().essential())
                .allMatch(entry -> allows("amr_properties." + entry.getKey()));
    }

    private static DisclosureMode mostRestrictive(DisclosureMode first, DisclosureMode second) {
        if (first == DisclosureMode.NEVER || second == DisclosureMode.NEVER) {
            return DisclosureMode.NEVER;
        }
        if (first == DisclosureMode.REQUESTED || second == DisclosureMode.REQUESTED) {
            return DisclosureMode.REQUESTED;
        }
        return DisclosureMode.DEFAULT;
    }

    private static PolicyScope parse(String value) {
        if (value == null || value.isBlank()) {
            return PolicyScope.permissive();
        }
        if (WILDCARD.equals(value.trim())) {
            return PolicyScope.permissive();
        }
        if (DENY_ALL.equalsIgnoreCase(value.trim())) {
            return PolicyScope.denyAllScope();
        }
        LinkedHashMap<String, DisclosureMode> modes = new LinkedHashMap<>();
        Arrays.stream(value.split("[,\\s]+"))
                .map(item -> item.trim().toLowerCase(Locale.ROOT))
                .filter(item -> !item.isBlank())
                .forEach(item -> {
                    int separator = item.indexOf(':');
                    if (separator > 0 && separator < item.length() - 1) {
                        String mode = item.substring(0, separator);
                        String path = item.substring(separator + 1);
                        DisclosureMode disclosureMode = switch (mode) {
                            case MODE_DEFAULT -> DisclosureMode.DEFAULT;
                            case MODE_REQUESTED -> DisclosureMode.REQUESTED;
                            case MODE_NEVER -> DisclosureMode.NEVER;
                            default -> null;
                        };
                        if (disclosureMode != null) {
                            modes.put(path, disclosureMode);
                            return;
                        }
                    }
                    // Entries written by older versions are allow-list paths.
                    modes.put(item, DisclosureMode.DEFAULT);
                });
        return modes.isEmpty() ? PolicyScope.permissive() : PolicyScope.configured(modes);
    }

    public enum DisclosureMode {
        DEFAULT,
        REQUESTED,
        NEVER
    }

    private record PolicyScope(boolean configured, boolean denyAll, Map<String, DisclosureMode> modes) {

        private PolicyScope {
            modes = Map.copyOf(modes);
        }

        private static PolicyScope permissive() {
            return new PolicyScope(false, false, Map.of());
        }

        private static PolicyScope denyAllScope() {
            return new PolicyScope(true, true, Map.of());
        }

        private static PolicyScope configured(Map<String, DisclosureMode> modes) {
            return new PolicyScope(true, false, modes);
        }

        private DisclosureMode mode(String path) {
            if (!configured) {
                return DisclosureMode.DEFAULT;
            }
            if (denyAll) {
                return DisclosureMode.NEVER;
            }
            return modes.getOrDefault(path.toLowerCase(Locale.ROOT), DisclosureMode.NEVER);
        }
    }
}
