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
package org.keycloak.protocol.oidc.utils;

import java.util.List;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AcrUtilsTest {

    @Test
    void readsAcrWithoutDeserializingAnUnrelatedExtendedClaim() {
        String claims = """
                {
                  "id_token": {
                    "acr": { "essential": true, "values": ["loa-2"] },
                    "amr_details": {
                      "essential": true,
                      "amr_identifier": { "value": "pwd" },
                      "amr_metadata": { "time": { "essential": true } }
                    }
                  }
                }
                """;

        assertEquals(List.of("loa-2"), AcrUtils.getRequiredAcrValues(claims));
    }
}
