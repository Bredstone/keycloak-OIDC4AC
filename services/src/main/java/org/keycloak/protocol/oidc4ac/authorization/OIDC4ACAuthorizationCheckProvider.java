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
package org.keycloak.protocol.oidc4ac.authorization;

import jakarta.ws.rs.core.Response;

import org.keycloak.OAuthErrorException;
import org.keycloak.protocol.oidc.endpoints.AuthorizationEndpointCheckProvider;
import org.keycloak.protocol.oidc.endpoints.AuthorizationEndpointChecker;
import org.keycloak.protocol.oidc.endpoints.AuthorizationEndpointChecker.AuthorizationCheckException;
import org.keycloak.protocol.oidc4ac.request.AmrDetailsRequestException;
import org.keycloak.protocol.oidc4ac.request.AmrDetailsRequestParser;

/**
 * Validates the OIDC4AC subset of the claims parameter after Keycloak has
 * validated the client and redirect URI.
 */
public class OIDC4ACAuthorizationCheckProvider implements AuthorizationEndpointCheckProvider {

    @Override
    public void check(AuthorizationEndpointChecker context) throws AuthorizationCheckException {
        try {
            AmrDetailsRequestParser.parseClaimsParameter(context.getAuthorizationEndpointRequest().getClaims());
        } catch (AmrDetailsRequestException e) {
            throw new AuthorizationCheckException(Response.Status.BAD_REQUEST, OAuthErrorException.INVALID_REQUEST,
                    "Invalid amr_details claim request");
        }
    }

    @Override
    public void close() {
    }
}
