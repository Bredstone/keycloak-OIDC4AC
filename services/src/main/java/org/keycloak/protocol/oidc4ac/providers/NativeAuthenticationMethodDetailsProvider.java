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
                new AuthenticationMethodCapability("pwd", Set.of("pwd_derivation_algorithm", "pwd_iterations"), Map.of()),
                new AuthenticationMethodCapability("otp", Set.of("otp_algorithm", "otp_delivery_method", "otp_format",
                        "otp_length", "otp_time_to_live"), Map.of("otp_algorithm", Set.of("HOTP", "TOTP"),
                        "otp_delivery_method", Set.of("app"), "otp_format", Set.of("numeric"))),
                new AuthenticationMethodCapability("pop", Set.of(), Map.of()));
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
            return Optional.of(new AuthenticationMethodDetails("pop", context.executionTime(), Map.of(), Optional.empty()));
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
            return new AuthenticationMethodDetails("pwd", context.executionTime(), Map.of(), Optional.empty());
        }

        Map<String, Object> properties = new java.util.LinkedHashMap<>();
        properties.put("pwd_derivation_algorithm", credential.getPasswordCredentialData().getAlgorithm());
        if (credential.getPasswordCredentialData().getHashIterations() > 0) {
            properties.put("pwd_iterations", credential.getPasswordCredentialData().getHashIterations());
        }
        return new AuthenticationMethodDetails("pwd", context.executionTime(), Map.of(), Optional.of(properties));
    }

    private AuthenticationMethodDetails otpDetails(AuthenticationMethodDetailsContext context) {
        String credentialId = context.selectedCredentialId();
        if (credentialId == null || credentialId.isBlank()) {
            return new AuthenticationMethodDetails("otp", context.executionTime(), Map.of(), Optional.empty());
        }

        CredentialModel credential = context.user().credentialManager().getStoredCredentialById(credentialId);
        if (credential == null || !OTPCredentialModel.TYPE.equals(credential.getType())) {
            return new AuthenticationMethodDetails("otp", context.executionTime(), Map.of(), Optional.empty());
        }

        try {
            OTPCredentialData data = JsonSerialization.readValue(credential.getCredentialData(), OTPCredentialData.class);
            String mode = otpMode(data);
            if (mode == null || data.getDigits() <= 0 || (OTPCredentialModel.TOTP.equals(data.getSubType()) && data.getPeriod() <= 0)) {
                return new AuthenticationMethodDetails("otp", context.executionTime(), Map.of(), Optional.empty());
            }

            Map<String, Object> properties = new LinkedHashMap<>();
            properties.put("otp_length", data.getDigits());
            properties.put("otp_algorithm", mode);
            properties.put("otp_format", "numeric");
            properties.put("otp_delivery_method", "app");
            if (OTPCredentialModel.TOTP.equals(data.getSubType())) {
                properties.put("otp_time_to_live", data.getPeriod());
            }
            return new AuthenticationMethodDetails("otp", context.executionTime(), Map.of(), Optional.of(properties));
        } catch (IOException | RuntimeException e) {
            // A malformed or unavailable credential must not cause login to
            // fail or produce a guessed/incomplete properties object.
            return new AuthenticationMethodDetails("otp", context.executionTime(), Map.of(), Optional.empty());
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
}
