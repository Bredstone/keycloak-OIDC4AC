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
package org.keycloak.protocol.oidc4ac.event;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.Test;
import org.keycloak.protocol.oidc4ac.model.AuthenticationEvent;
import org.keycloak.protocol.oidc4ac.model.AuthenticationMethodExecution;
import org.keycloak.util.JsonSerialization;

public class AuthenticationEventSnapshotCodecTest {

    @Test
    public void roundTripsImmutableEventWithMandatoryTimeAndOptionalProperties() throws Exception {
        AuthenticationEvent original = new AuthenticationEvent(List.of(
                new AuthenticationMethodExecution("pwd", Instant.parse("2026-07-25T12:00:00Z"),
                        Map.of("issuer", JsonSerialization.mapper.valueToTree("local"),
                                "location", JsonSerialization.mapper.valueToTree(Map.of("ip_address", "203.0.113.7"))),
                        Optional.empty())));

        String encoded = AuthenticationEventSnapshotCodec.serialize(original);
        AuthenticationEvent decoded = AuthenticationEventSnapshotCodec.deserialize(encoded);

        assertTrue(encoded.contains("\"time\""));
        assertFalse(encoded.contains("amr_properties"));
        assertEquals(original, decoded);
        assertEquals(JsonSerialization.mapper.valueToTree(Map.of("ip_address", "203.0.113.7")),
                decoded.executions().get(0).metadataValue("location").orElseThrow());
    }
}
