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
package org.keycloak.admin.ui.rest.model;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Admin Console representation for experimental OIDC4AC realm/client policy settings. */
public class Oidc4acConfigurationRepresentation {

    private String browserFlowAlias;
    private String factorFlowAlias;
    private String plannerExecutionId;
    private String plannerConfigId;
    private boolean plannerConfigured;
    private Boolean enabled;
    private String clientId;
    private Boolean realmPolicyUpdate;
    private Boolean clientPolicyUpdate;
    private List<String> clientIds = new ArrayList<>();
    private Map<String, String> realmDisclosureModes = new LinkedHashMap<>();
    private Map<String, String> clientDisclosureModes = new LinkedHashMap<>();

    public String getBrowserFlowAlias() {
        return browserFlowAlias;
    }

    public void setBrowserFlowAlias(String browserFlowAlias) {
        this.browserFlowAlias = browserFlowAlias;
    }

    public String getFactorFlowAlias() {
        return factorFlowAlias;
    }

    public void setFactorFlowAlias(String factorFlowAlias) {
        this.factorFlowAlias = factorFlowAlias;
    }

    public String getPlannerExecutionId() {
        return plannerExecutionId;
    }

    public void setPlannerExecutionId(String plannerExecutionId) {
        this.plannerExecutionId = plannerExecutionId;
    }

    public String getPlannerConfigId() {
        return plannerConfigId;
    }

    public void setPlannerConfigId(String plannerConfigId) {
        this.plannerConfigId = plannerConfigId;
    }

    public boolean isPlannerConfigured() {
        return plannerConfigured;
    }

    public void setPlannerConfigured(boolean plannerConfigured) {
        this.plannerConfigured = plannerConfigured;
    }

    public Boolean getEnabled() {
        return enabled;
    }

    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public Boolean getRealmPolicyUpdate() {
        return realmPolicyUpdate;
    }

    public void setRealmPolicyUpdate(Boolean realmPolicyUpdate) {
        this.realmPolicyUpdate = realmPolicyUpdate;
    }

    public Boolean getClientPolicyUpdate() {
        return clientPolicyUpdate;
    }

    public void setClientPolicyUpdate(Boolean clientPolicyUpdate) {
        this.clientPolicyUpdate = clientPolicyUpdate;
    }

    public List<String> getClientIds() {
        return clientIds;
    }

    public void setClientIds(List<String> clientIds) {
        this.clientIds = clientIds == null ? new ArrayList<>() : new ArrayList<>(clientIds);
    }

    public Map<String, String> getRealmDisclosureModes() {
        return realmDisclosureModes;
    }

    public void setRealmDisclosureModes(Map<String, String> realmDisclosureModes) {
        this.realmDisclosureModes = copyModes(realmDisclosureModes);
    }

    public Map<String, String> getClientDisclosureModes() {
        return clientDisclosureModes;
    }

    public void setClientDisclosureModes(Map<String, String> clientDisclosureModes) {
        this.clientDisclosureModes = copyModes(clientDisclosureModes);
    }

    private static Map<String, String> copyModes(Map<String, String> modes) {
        return modes == null ? new LinkedHashMap<>() : new LinkedHashMap<>(modes);
    }
}
