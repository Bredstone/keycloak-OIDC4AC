/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package org.keycloak.protocol.oidc4ac.disclosure;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.keycloak.protocol.oidc4ac.delivery.AmrDetailsProjection;
import org.keycloak.protocol.oidc4ac.model.AuthenticationEvent;
import org.keycloak.protocol.oidc4ac.model.AuthenticationMethodExecution;
import org.keycloak.protocol.oidc4ac.request.AmrDetailsClaimRequest;
import org.keycloak.protocol.oidc4ac.request.AmrDetailsClaimsRequest;
import org.keycloak.protocol.oidc4ac.request.AmrDetailsRequestParser;
import org.keycloak.util.JsonSerialization;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class OIDC4ACDisclosurePolicyTest {

    @Test
    public void realmAndClientPoliciesIntersectAndMandatoryFieldsRemain() throws Exception {
        OIDC4ACDisclosurePolicy policy = OIDC4ACDisclosurePolicy.forAttributeValues(
                "amr_metadata.issuer,amr_properties.pwd_derivation_algorithm",
                "amr_metadata.issuer");
        AmrDetailsClaimRequest request = request();
        AuthenticationEvent event = event();

        Map<String, Object> detail = AmrDetailsProjection.project(request, event, policy).get(0);
        @SuppressWarnings("unchecked")
        Map<String, Object> metadata = (Map<String, Object>) detail.get("amr_metadata");

        assertTrue(metadata.containsKey("time"));
        assertTrue(metadata.containsKey("issuer"));
        assertFalse(detail.containsKey("amr_properties"));
    }

    @Test
    public void deniedEssentialPropertyMakesRequestUnrepresentable() throws Exception {
        OIDC4ACDisclosurePolicy policy = OIDC4ACDisclosurePolicy.forAttributeValues("*", "amr_metadata.issuer");
        AmrDetailsClaimsRequest requests = AmrDetailsRequestParser.parseClaimsParameter("""
                {"id_token":{"amr_details":{"essential":true,"amr_identifier":{"value":"pwd"},
                "amr_metadata":{"time":null},"amr_properties":{"pwd_derivation_algorithm":{"essential":true}}}}}
                """);

        assertFalse(policy.essentialRequestsRepresentable(requests));
    }

    @Test
    public void oneOfRemainsRepresentableWhenOneBranchIsAllowed() throws Exception {
        OIDC4ACDisclosurePolicy policy = OIDC4ACDisclosurePolicy.forAttributeValues("*", "amr_properties.otp_algorithm");
        AmrDetailsClaimsRequest requests = AmrDetailsRequestParser.parseClaimsParameter("""
                {"id_token":{"amr_details":{"essential":true,"one_of":[
                {"amr_identifier":{"value":"pwd"},"amr_metadata":{"time":null},
                 "amr_properties":{"pwd_derivation_algorithm":{"essential":true}}},
                {"amr_identifier":{"value":"otp"},"amr_metadata":{"time":null},
                 "amr_properties":{"otp_algorithm":{"essential":true}}}]}}}
                """);

        assertTrue(policy.essentialRequestsRepresentable(requests));
    }

    @Test
    public void explicitDenyAllBlocksOptionalFieldsButNotMandatoryEventFields() throws Exception {
        OIDC4ACDisclosurePolicy policy = OIDC4ACDisclosurePolicy.forAttributeValues(
                OIDC4ACDisclosurePolicy.DENY_ALL, OIDC4ACDisclosurePolicy.DENY_ALL);

        Map<String, Object> detail = AmrDetailsProjection.project(request(), event(), policy).get(0);

        assertTrue(detail.containsKey("amr_identifier"));
        @SuppressWarnings("unchecked")
        Map<String, Object> metadata = (Map<String, Object>) detail.get("amr_metadata");
        assertTrue(metadata.containsKey("time"));
        assertFalse(detail.containsKey("amr_properties"));
    }

    @Test
    public void perFieldModesDistinguishDefaultRequestedAndNever() {
        OIDC4ACDisclosurePolicy policy = OIDC4ACDisclosurePolicy.forAttributeValues(
                "default:amr_metadata.issuer,requested:amr_properties.pwd_iterations,never:amr_properties.pwd_derivation_algorithm",
                OIDC4ACDisclosurePolicy.WILDCARD);

        assertTrue(policy.allowsByDefault("amr_metadata.issuer"));
        assertFalse(policy.allowsByDefault("amr_properties.pwd_iterations"));
        assertTrue(policy.allows("amr_properties.pwd_iterations"));
        assertFalse(policy.allows("amr_properties.pwd_derivation_algorithm"));
        assertFalse(policy.allows("amr_properties.unconfigured"));
    }

    @Test
    public void realmAndClientModesUseMostRestrictiveValue() {
        OIDC4ACDisclosurePolicy policy = OIDC4ACDisclosurePolicy.forAttributeValues(
                "default:amr_metadata.issuer,requested:amr_properties.pwd_iterations",
                "default:amr_metadata.issuer,never:amr_properties.pwd_iterations");

        assertTrue(policy.allowsByDefault("amr_metadata.issuer"));
        assertFalse(policy.allows("amr_properties.pwd_iterations"));
    }

    @Test
    public void explicitModesRoundTripThroughTheStoredRepresentation() {
        Map<String, String> modes = Map.of(
                "amr_metadata.issuer", OIDC4ACDisclosurePolicy.MODE_DEFAULT,
                "amr_properties.pwd_iterations", OIDC4ACDisclosurePolicy.MODE_REQUESTED,
                "amr_properties.pwd_derivation_algorithm", OIDC4ACDisclosurePolicy.MODE_NEVER);

        assertEquals(modes, OIDC4ACDisclosurePolicy.parseModes(OIDC4ACDisclosurePolicy.serializeModes(modes)));
    }

    private static AmrDetailsClaimRequest request() throws Exception {
        return AmrDetailsRequestParser.parseClaimsParameter("""
                {"id_token":{"amr_details":{"amr_identifier":{"value":"pwd"},"amr_metadata":{"time":null,"issuer":null},
                "amr_properties":{"pwd_derivation_algorithm":null}}}}
                """).idToken().orElseThrow();
    }

    private static AuthenticationEvent event() {
        return new AuthenticationEvent(List.of(new AuthenticationMethodExecution("pwd",
                Instant.parse("2026-07-25T12:00:00Z"), Map.of("issuer", text("local")),
                Optional.of(Map.of("pwd_derivation_algorithm", text("argon2id"))))));
    }

    private static com.fasterxml.jackson.databind.JsonNode text(String value) {
        return JsonSerialization.mapper.valueToTree(value);
    }
}
