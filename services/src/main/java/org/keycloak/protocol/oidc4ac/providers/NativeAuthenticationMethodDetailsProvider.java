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
package org.keycloak.protocol.oidc4ac.providers;

import java.io.IOException;
import java.net.InetAddress;
import java.time.Instant;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.keycloak.authentication.authenticators.browser.OTPFormAuthenticatorFactory;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordFormFactory;
import org.keycloak.authentication.authenticators.browser.WebAuthnAuthenticatorFactory;
import org.keycloak.authentication.authenticators.browser.WebAuthnPasswordlessAuthenticatorFactory;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.PasswordCredentialProvider;
import org.keycloak.credential.PasswordCredentialProviderFactory;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.credential.WebAuthnCredentialModel;
import org.keycloak.models.credential.dto.OTPCredentialData;
import org.keycloak.protocol.oidc4ac.spi.AuthenticationMethodCapability;
import org.keycloak.protocol.oidc4ac.spi.AuthenticationMethodDetails;
import org.keycloak.protocol.oidc4ac.spi.AuthenticationMethodDetailsContext;
import org.keycloak.protocol.oidc4ac.spi.AuthenticationMethodDetailsProvider;
import org.keycloak.services.Urls;
import org.keycloak.util.JsonSerialization;

/**
 * Native password, OTP, and WebAuthn detail mappings. Authentication remains
 * in the native authenticators; this provider emits only verified safe facts.
 */
public class NativeAuthenticationMethodDetailsProvider implements AuthenticationMethodDetailsProvider {

    private static final Set<String> PASSWORD_EXECUTIONS = Set.of(UsernamePasswordFormFactory.PROVIDER_ID);
    private static final Set<String> OTP_EXECUTIONS = Set.of(OTPFormAuthenticatorFactory.PROVIDER_ID);
    private static final Set<String> WEBAUTHN_EXECUTIONS = Set.of(WebAuthnAuthenticatorFactory.PROVIDER_ID,
            WebAuthnPasswordlessAuthenticatorFactory.PROVIDER_ID, "passkeys-authenticator", UsernamePasswordFormFactory.PROVIDER_ID);

    @Override
    public Collection<AuthenticationMethodCapability> getCapabilities() {
        return List.of(
                new AuthenticationMethodCapability("pwd", Set.of("pwd_derivation_algorithm", "pwd_iterations",
                        "pwd_last_updated_at"), Set.of("iss", "location"), Map.of(), Set.of("ip_address")),
                new AuthenticationMethodCapability("otp", Set.of("otp_algorithm", "otp_delivery_method", "otp_format",
                        "otp_length", "otp_time_to_live"), Set.of("iss", "location"), Map.of("otp_algorithm", Set.of("HOTP", "TOTP"),
                        "otp_delivery_method", Set.of("app"), "otp_format", Set.of("numeric")), Set.of("ip_address")),
                new AuthenticationMethodCapability("pop", Set.of(), Set.of("iss", "location"), Map.of(), Set.of("ip_address")));
    }

    @Override
    public boolean supports(AuthenticationMethodDetailsContext context) {
        String credentialType = context.credentialType();
        return PASSWORD_EXECUTIONS.contains(context.authenticatorProviderId()) && PasswordCredentialModel.TYPE.equals(credentialType)
                || OTP_EXECUTIONS.contains(context.authenticatorProviderId()) && "otp".equals(credentialType)
                || WEBAUTHN_EXECUTIONS.contains(context.authenticatorProviderId())
                        && (WebAuthnCredentialModel.TYPE_TWOFACTOR.equals(credentialType)
                                || WebAuthnCredentialModel.TYPE_PASSWORDLESS.equals(credentialType));
    }

    @Override
    public Optional<AuthenticationMethodDetails> describeSuccessfulExecution(AuthenticationMethodDetailsContext context) {
        if (PASSWORD_EXECUTIONS.contains(context.authenticatorProviderId()) && PasswordCredentialModel.TYPE.equals(context.credentialType())) {
            return Optional.of(passwordDetails(context));
        }
        if (OTP_EXECUTIONS.contains(context.authenticatorProviderId()) && "otp".equals(context.credentialType())) {
            return Optional.of(otpDetails(context));
        }
        if (WEBAUTHN_EXECUTIONS.contains(context.authenticatorProviderId())
                && (WebAuthnCredentialModel.TYPE_TWOFACTOR.equals(context.credentialType())
                        || WebAuthnCredentialModel.TYPE_PASSWORDLESS.equals(context.credentialType()))) {
            // A verified WebAuthn assertion establishes proof of possession only.
            return Optional.of(new AuthenticationMethodDetails("pop", context.executionTime(), metadata(context), Optional.empty()));
        }
        return Optional.empty();
    }

    @Override
    public void close() {
    }

    private AuthenticationMethodDetails passwordDetails(AuthenticationMethodDetailsContext context) {
        PasswordCredentialProvider provider = (PasswordCredentialProvider) context.session()
                .getProvider(CredentialProvider.class, PasswordCredentialProviderFactory.PROVIDER_ID);
        PasswordCredentialModel credential = provider.getPassword(context.realm(), context.user());
        if (credential == null || credential.getPasswordCredentialData() == null
                || credential.getPasswordCredentialData().getAlgorithm() == null
                || credential.getPasswordCredentialData().getAlgorithm().isBlank()) {
            return new AuthenticationMethodDetails("pwd", context.executionTime(), metadata(context), Optional.empty());
        }

        Map<String, Object> properties = new java.util.LinkedHashMap<>();
        properties.put("pwd_derivation_algorithm", credential.getPasswordCredentialData().getAlgorithm());
        if (credential.getPasswordCredentialData().getHashIterations() > 0) {
            properties.put("pwd_iterations", credential.getPasswordCredentialData().getHashIterations());
        }
        if (credential.getCreatedDate() != null && credential.getCreatedDate() > 0) {
            properties.put("pwd_last_updated_at", Instant.ofEpochMilli(credential.getCreatedDate()).toString());
        }
        return new AuthenticationMethodDetails("pwd", context.executionTime(), metadata(context), Optional.of(properties));
    }

    private AuthenticationMethodDetails otpDetails(AuthenticationMethodDetailsContext context) {
        String credentialId = context.selectedCredentialId();
        if (credentialId == null || credentialId.isBlank()) {
            return new AuthenticationMethodDetails("otp", context.executionTime(), metadata(context), Optional.empty());
        }

        CredentialModel credential = context.user().credentialManager().getStoredCredentialById(credentialId);
        if (credential == null || !OTPCredentialModel.TYPE.equals(credential.getType())) {
            return new AuthenticationMethodDetails("otp", context.executionTime(), metadata(context), Optional.empty());
        }

        try {
            OTPCredentialData data = JsonSerialization.readValue(credential.getCredentialData(), OTPCredentialData.class);
            String mode = otpMode(data);
            if (mode == null || data.getDigits() <= 0 || (OTPCredentialModel.TOTP.equals(data.getSubType()) && data.getPeriod() <= 0)) {
                return new AuthenticationMethodDetails("otp", context.executionTime(), metadata(context), Optional.empty());
            }

            Map<String, Object> properties = new LinkedHashMap<>();
            properties.put("otp_length", data.getDigits());
            properties.put("otp_algorithm", mode);
            properties.put("otp_format", "numeric");
            properties.put("otp_delivery_method", "app");
            if (OTPCredentialModel.TOTP.equals(data.getSubType())) {
                properties.put("otp_time_to_live", data.getPeriod());
            }
            return new AuthenticationMethodDetails("otp", context.executionTime(), metadata(context), Optional.of(properties));
        } catch (IOException | RuntimeException e) {
            // A malformed or unavailable credential must not cause login to
            // fail or produce a guessed/incomplete properties object.
            return new AuthenticationMethodDetails("otp", context.executionTime(), metadata(context), Optional.empty());
        }
    }

    private String otpMode(OTPCredentialData data) {
        if (OTPCredentialModel.TOTP.equals(data.getSubType())) {
            return "TOTP";
        }
        if (OTPCredentialModel.HOTP.equals(data.getSubType())) {
            return "HOTP";
        }
        return null;
    }

    /**
     * Returns only facts available from the current Keycloak request context.
     * The network origin is represented using the protocol's structured
     * {@code amr_metadata.location} object; it is never emitted as a scalar
     * metadata value. Geospatial and postal fields are intentionally omitted
     * because Keycloak does not establish them during native authentication.
     */
    private Map<String, Object> metadata(AuthenticationMethodDetailsContext context) {
        Map<String, Object> metadata = new LinkedHashMap<>();
        try {
            String issuer = Urls.realmIssuer(context.session().getContext().getUri().getBaseUri(), context.realm().getName());
            if (issuer != null && !issuer.isBlank()) {
                metadata.put("iss", issuer);
            }
        } catch (RuntimeException ignored) {
            // A provider adapter must never make authentication fail because
            // request context metadata is unavailable (for example in SSO or
            // a non-HTTP execution).
        }
        try {
            String remoteAddress = context.session().getContext().getConnection().getRemoteAddr();
            if (isIpAddress(remoteAddress)) {
                metadata.put("location", Map.of("ip_address", remoteAddress));
            }
        } catch (RuntimeException ignored) {
            // The network origin is optional and may be unavailable in
            // non-HTTP execution contexts.
        }
        return Map.copyOf(metadata);
    }

    private boolean isIpAddress(String value) {
        if (value == null || value.isBlank()) {
            return false;
        }
        if (value.indexOf(':') >= 0) {
            try {
                // A colon-bearing literal is parsed without DNS resolution;
                // zone identifiers are excluded because the claim carries an
                // address, not a host-interface reference.
                return !value.contains("%") && InetAddress.getByName(value).getHostAddress() != null;
            } catch (IOException | RuntimeException ignored) {
                return false;
            }
        }
        String[] octets = value.split("\\.", -1);
        if (octets.length != 4) {
            return false;
        }
        for (String octet : octets) {
            if (octet.isEmpty() || octet.length() > 3 || !octet.chars().allMatch(Character::isDigit)) {
                return false;
            }
            try {
                if (Integer.parseInt(octet) > 255) {
                    return false;
                }
            } catch (NumberFormatException ignored) {
                return false;
            }
        }
        return true;
    }
}
