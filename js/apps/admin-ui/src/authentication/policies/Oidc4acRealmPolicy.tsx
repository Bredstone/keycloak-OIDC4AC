import { fetchWithError } from "@keycloak/keycloak-admin-client";
import {
  Alert,
  Card,
  CardBody,
  CardTitle,
  HelperText,
  HelperTextItem,
  PageSection,
  Title,
} from "@patternfly/react-core";
import { useAlerts, useEnvironment } from "@keycloak/keycloak-ui-shared";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useAdminClient } from "../../admin-client";
import { FixedButtonsGroup } from "../../components/form/FixedButtonGroup";
import { FormAccess } from "../../components/form/FormAccess";
import { useRealm } from "../../context/realm-context/RealmContext";
import type { Environment } from "../../environment-types";
import { addTrailingSlash } from "../../util";
import { getAuthorizationHeaders } from "../../utils/getAuthorizationHeaders";
import {
  capabilitiesFromDiscovery,
  DEFAULT_DISCLOSURE_MODE,
  disclosureModesFromCapabilities,
  DisclosureFields,
  type Capability,
  type DisclosureMode as FieldDisclosureMode,
} from "./Oidc4acDisclosureFields";
import style from "./oidc4ac-policy.module.css";

type Configuration = {
  enabled?: boolean;
  browserFlowAlias?: string;
  factorFlowAlias?: string;
  plannerConfigured?: boolean;
  realmDisclosureModes?: Record<string, FieldDisclosureMode>;
};

export function Oidc4acRealmPolicy() {
  const { t } = useTranslation();
  const { realm } = useRealm();
  const { adminClient } = useAdminClient();
  const { environment } = useEnvironment<Environment>();
  const { addAlert, addError } = useAlerts();
  const [capabilities, setCapabilities] = useState<Capability[]>([]);
  const [planner, setPlanner] = useState<Configuration>();
  const [realmFieldModes, setRealmFieldModes] = useState<
    Record<string, FieldDisclosureMode>
  >({});
  const [enabled, setEnabled] = useState(true);
  const [initial, setInitial] = useState<Record<string, FieldDisclosureMode>>(
    {},
  );
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string>();

  const endpoint = `${addTrailingSlash(adminClient.baseUrl)}admin/realms/${realm}/ui-ext/oidc4ac`;

  useEffect(() => {
    void (async () => {
      try {
        const [configResponse, discoveryResponse] = await Promise.all([
          fetchWithError(endpoint, {
            headers: getAuthorizationHeaders(
              await adminClient.getAccessToken(),
            ),
          }).then((response) => response.json() as Promise<Configuration>),
          fetchWithError(
            `${addTrailingSlash(environment.serverBaseUrl)}realms/${realm}/.well-known/openid-configuration`,
          ).then(
            (response) => response.json() as Promise<Record<string, unknown>>,
          ),
        ]);
        const discoveredCapabilities =
          capabilitiesFromDiscovery(discoveryResponse);
        const configuredModes = configResponse.realmDisclosureModes || {};
        const initialModes = {
          ...disclosureModesFromCapabilities(discoveredCapabilities),
          ...configuredModes,
        };
        const oidc4acEnabled = configResponse.enabled ?? true;
        setPlanner(configResponse);
        setCapabilities(discoveredCapabilities);
        setRealmFieldModes(initialModes);
        setEnabled(oidc4acEnabled);
        setInitial(initialModes);
      } catch (cause) {
        setError(cause instanceof Error ? cause.message : String(cause));
      } finally {
        setLoading(false);
      }
    })();
  }, [adminClient, endpoint, environment.serverBaseUrl, realm]);

  const changeFieldMode = (path: string, fieldMode: FieldDisclosureMode) =>
    setRealmFieldModes((current) => ({ ...current, [path]: fieldMode }));

  const save = async () => {
    setSaving(true);
    setError(undefined);
    try {
      await fetchWithError(endpoint, {
        method: "PUT",
        headers: {
          ...getAuthorizationHeaders(await adminClient.getAccessToken()),
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          realmDisclosureModes: realmFieldModes,
          realmPolicyUpdate: true,
          clientPolicyUpdate: false,
        }),
      });
      setInitial(realmFieldModes);
      addAlert(t("itemSaveSuccessful"));
    } catch (cause) {
      addError("itemSaveError", cause);
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setSaving(false);
    }
  };

  const reset = () => {
    setRealmFieldModes(initial);
    setError(undefined);
  };

  return (
    <PageSection className={style.page}>
      <Title headingLevel="h2" size="xl" className="pf-v5-u-mb-lg">
        {t("oidc4acPolicy")}
      </Title>
      {error && (
        <Alert
          variant="danger"
          title={t("error")}
          isInline
          className="pf-v5-u-mb-lg"
        >
          {error}
        </Alert>
      )}
      <Card className="pf-v5-u-mb-md">
        <CardTitle>Authentication planner status</CardTitle>
        <CardBody>
          {!enabled ? (
            <Alert variant="warning" isInline title="Disabled for this realm">
              OIDC4AC is disabled. The configured browser planner and disclosure
              policy are retained, but they are not used until this switch is
              enabled.
            </Alert>
          ) : planner?.plannerConfigured ? (
            <Alert variant="success" isInline title="Enabled">
              The OIDC4AC factor planner was detected in the{" "}
              <strong>{planner.browserFlowAlias}</strong> authentication flow.
              It routes requested factors through{" "}
              <strong>
                {planner.factorFlowAlias || "the configured factor flow"}
              </strong>
              .
            </Alert>
          ) : (
            <Alert
              variant="warning"
              isInline
              title="Informational disclosure only"
            >
              No enabled OIDC4AC factor planner was found in a browser flow.
              Authentication requests can still receive informational
              authentication-event details, but requested factors will not be
              selected dynamically.
            </Alert>
          )}
          <HelperText className="pf-v5-u-mt-md">
            <HelperTextItem>
              Configure or enable the planner from{" "}
              <strong>Authentication → Flows</strong>. This page only controls
              disclosure policy; it does not create or edit authentication-flow
              executions.
            </HelperTextItem>
          </HelperText>
        </CardBody>
      </Card>

      <FormAccess
        className={style.fullWidthForm}
        role="manage-realm"
        onSubmit={(event) => {
          event.preventDefault();
          void save();
        }}
      >
        <div className="pf-v5-u-mt-md">
          <DisclosureFields
            capabilities={capabilities}
            modes={realmFieldModes}
            fallbackMode={DEFAULT_DISCLOSURE_MODE}
            onModeChange={changeFieldMode}
            disabled={loading}
            idPrefix="oidc4ac-realm-field"
          />
        </div>
        <FixedButtonsGroup
          name="oidc4ac-realm-policy"
          reset={reset}
          isSubmit
          isDisabled={loading || saving}
        />
      </FormAccess>
    </PageSection>
  );
}
