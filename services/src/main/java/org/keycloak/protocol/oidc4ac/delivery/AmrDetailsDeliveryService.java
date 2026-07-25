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
package org.keycloak.protocol.oidc4ac.delivery;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;

import org.keycloak.common.Profile;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc4ac.OIDC4ACConstants;
import org.keycloak.protocol.oidc4ac.event.AuthenticationEventSnapshotStore;
import org.keycloak.protocol.oidc4ac.request.AmrDetailsClaimRequest;
import org.keycloak.protocol.oidc4ac.request.AmrDetailsRequestException;
import org.keycloak.protocol.oidc4ac.request.AmrDetailsRequestParser;
import org.keycloak.representations.JsonWebToken;

/** Adds a requested ID Token or UserInfo claim from a stored grant snapshot. */
public final class AmrDetailsDeliveryService {

    private AmrDetailsDeliveryService() {
    }

    public static void applyToIdToken(JsonWebToken token, ClientSessionContext clientSessionContext) {
        apply(token, clientSessionContext, true);
    }

    public static void applyToUserInfo(JsonWebToken token, ClientSessionContext clientSessionContext) {
        apply(token, clientSessionContext, false);
    }

    private static void apply(JsonWebToken token, ClientSessionContext clientSessionContext, boolean idToken) {
        if (!Profile.isFeatureEnabled(Profile.Feature.OIDC4AC)) {
            return;
        }
        AuthenticatedClientSessionModel clientSession = clientSessionContext.getClientSession();
        Optional<AmrDetailsClaimRequest> request;
        try {
            request = idToken
                    ? AmrDetailsRequestParser.parseClaimsParameter(clientSession.getNote(OIDCLoginProtocol.CLAIMS_PARAM)).idToken()
                    : AmrDetailsRequestParser.parseClaimsParameter(clientSession.getNote(OIDCLoginProtocol.CLAIMS_PARAM)).userInfo();
        } catch (AmrDetailsRequestException e) {
            return;
        }
        if (request.isEmpty()) {
            return;
        }

        AuthenticationEventSnapshotStore.client(clientSession).ifPresent(event -> {
            List<java.util.Map<String, Object>> details = AmrDetailsProjection.project(request.orElseThrow(), event);
            token.setOtherClaims(OIDC4ACConstants.AMR_DETAILS, details);
            ensureAmrContainsDetails(token, details);
        });
    }

    private static void ensureAmrContainsDetails(JsonWebToken token, List<java.util.Map<String, Object>> details) {
        LinkedHashSet<String> identifiers = new LinkedHashSet<>();
        Object existing = token.getOtherClaims().get("amr");
        if (existing instanceof Collection<?> values) {
            values.forEach(value -> identifiers.add(String.valueOf(value)));
        } else if (existing instanceof String value) {
            identifiers.add(value);
        } else if (existing instanceof String[] values) {
            java.util.Collections.addAll(identifiers, values);
        }
        details.forEach(detail -> identifiers.add((String) detail.get("amr_identifier")));
        token.setOtherClaims("amr", List.copyOf(new ArrayList<>(identifiers)));
    }
}
