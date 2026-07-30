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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.Test;
import org.keycloak.protocol.oidc.representations.OIDCConfigurationRepresentation;
import org.keycloak.protocol.oidc4ac.spi.AuthenticationMethodCapability;

public class OIDC4ACDiscoveryMetadataTest {

    @Test
    public void advertisesOnlyFiniteClosedStringVocabularies() {
        OIDCConfigurationRepresentation configuration = new OIDCConfigurationRepresentation();
        configuration.setClaimsSupported(List.of("sub"));

        OIDC4ACDiscoveryMetadata.apply(configuration, List.of(
                new AuthenticationMethodCapability("pwd", Set.of("pwd_iterations", "pwd_derivation_algorithm",
                        "pwd_last_updated_at"), Set.of("iss", "time"), Map.of()),
                new AuthenticationMethodCapability("otp", Set.of("otp_algorithm"), Map.of("otp_algorithm", Set.of("HOTP", "TOTP")))));

        assertTrue(configuration.getClaimsSupported().contains("amr_details"));
        assertEquals(true, configuration.getOtherClaims().get("amr_details_request_supported"));
        assertEquals(List.of("otp", "pwd"), configuration.getOtherClaims().get("amr_identifiers_supported"));
        assertEquals(List.of("pwd_derivation_algorithm", "pwd_iterations", "pwd_last_updated_at"),
                configuration.getOtherClaims().get("pwd_properties_supported"));
        assertEquals(List.of("HOTP", "TOTP"), configuration.getOtherClaims().get("otp_algorithm_values_supported"));
        assertFalse(configuration.getOtherClaims().containsKey("pwd_iterations_values_supported"));
        assertEquals(List.of("iss"), configuration.getOtherClaims().get("pwd_metadata_supported"));
    }

    @Test
    public void canAdvertiseInformationalDisclosureWithoutRequestDrivenPlanner() {
        OIDCConfigurationRepresentation configuration = new OIDCConfigurationRepresentation();
        configuration.setClaimsSupported(List.of("sub"));

        OIDC4ACDiscoveryMetadata.apply(configuration,
                List.of(new AuthenticationMethodCapability("pwd", Set.of(), Map.of())), false);

        assertEquals(false, configuration.getOtherClaims().get("amr_details_request_supported"));
        assertTrue(configuration.getClaimsSupported().contains("amr_details"));
    }
}
