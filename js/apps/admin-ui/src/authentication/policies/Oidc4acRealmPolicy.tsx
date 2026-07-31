import { fetchWithError } from "@keycloak/keycloak-admin-client";
import {
  Alert,
  Card,
  CardBody,
  CardTitle,
  Divider,
  Form,
  FormGroup,
  HelperText,
  HelperTextItem,
  PageSection,
  Radio,
  Title,
} from "@patternfly/react-core";
import { useEnvironment } from "@keycloak/keycloak-ui-shared";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useAdminClient } from "../../admin-client";
import { FixedButtonsGroup } from "../../components/form/FixedButtonGroup";
import { useRealm } from "../../context/realm-context/RealmContext";
import type { Environment } from "../../environment-types";
import { addTrailingSlash } from "../../util";
import { getAuthorizationHeaders } from "../../utils/getAuthorizationHeaders";
import {
  capabilitiesFromDiscovery,
  DisclosureFields,
  type Capability,
} from "./Oidc4acDisclosureFields";
import style from "./oidc4ac-policy.module.css";

type DisclosureMode = "all" | "selected" | "none";

const modeOptions: Array<{
  value: DisclosureMode;
  label: string;
  description: string;
}> = [
  {
    value: "all",
    label: "Allow all supported optional fields",
    description:
      "The OP may disclose optional metadata and properties supported by each method.",
  },
  {
    value: "selected",
    label: "Allow only selected fields",
    description: "Only the fields selected below may be disclosed.",
  },
  {
    value: "none",
    label: "Do not disclose optional fields",
    description:
      "Only mandatory amr_identifier and amr_metadata.time remain available.",
  },
];

type Configuration = {
  enabled?: boolean;
  browserFlowAlias?: string;
  factorFlowAlias?: string;
  plannerConfigured?: boolean;
  realmDisclosureMode?: DisclosureMode;
  realmAllowedFields?: string[];
};

export function Oidc4acRealmPolicy() {
  const { t } = useTranslation();
  const { realm } = useRealm();
  const { adminClient } = useAdminClient();
  const { environment } = useEnvironment<Environment>();
  const [capabilities, setCapabilities] = useState<Capability[]>([]);
  const [planner, setPlanner] = useState<Configuration>();
  const [realmMode, setRealmMode] = useState<DisclosureMode>("all");
  const [realmFields, setRealmFields] = useState<Set<string>>(new Set());
  const [enabled, setEnabled] = useState(true);
  const [initial, setInitial] = useState({
    mode: "all" as DisclosureMode,
    fields: [] as string[],
  });
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
        const mode = configResponse.realmDisclosureMode || "all";
        const fields = configResponse.realmAllowedFields || [];
        const oidc4acEnabled = configResponse.enabled ?? true;
        setPlanner(configResponse);
        setCapabilities(capabilitiesFromDiscovery(discoveryResponse));
        setRealmMode(mode);
        setRealmFields(new Set(fields));
        setEnabled(oidc4acEnabled);
        setInitial({ mode, fields });
      } catch (cause) {
        setError(cause instanceof Error ? cause.message : String(cause));
      } finally {
        setLoading(false);
      }
    })();
  }, [adminClient, endpoint, environment.serverBaseUrl, realm]);

  const toggleField = (path: string) =>
    setRealmFields((current) => {
      const next = new Set(current);
      if (next.has(path)) next.delete(path);
      else next.add(path);
      return next;
    });

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
          realmDisclosureMode: realmMode,
          realmAllowedFields: Array.from(realmFields),
          realmPolicyUpdate: true,
          clientPolicyUpdate: false,
        }),
      });
      setInitial({
        mode: realmMode,
        fields: Array.from(realmFields),
      });
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setSaving(false);
    }
  };

  const reset = () => {
    setRealmMode(initial.mode);
    setRealmFields(new Set(initial.fields));
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
      <Card className="pf-v5-u-mb-lg">
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

      <Form
        className={style.fullWidthForm}
        onSubmit={(event) => {
          event.preventDefault();
          void save();
        }}
      >
        <Card>
          <CardTitle>Realm disclosure policy</CardTitle>
          <CardBody>
            <FormGroup label="Realm default" fieldId="oidc4ac-realm-mode">
              {modeOptions.map((option) => (
                <Radio
                  key={option.value}
                  id={`oidc4ac-realm-mode-${option.value}`}
                  name="oidc4ac-realm-mode"
                  label={option.label}
                  description={option.description}
                  isChecked={realmMode === option.value}
                  onChange={() => setRealmMode(option.value)}
                  isDisabled={loading}
                />
              ))}
            </FormGroup>
            <Divider className="pf-v5-u-my-lg" />
            <DisclosureFields
              capabilities={capabilities}
              selected={realmFields}
              onToggle={toggleField}
              disabled={loading || realmMode !== "selected"}
              idPrefix="oidc4ac-realm-field"
            />
          </CardBody>
        </Card>
        <FixedButtonsGroup
          name="oidc4ac-realm-policy"
          save={save}
          reset={reset}
          isDisabled={loading || saving}
        />
      </Form>
    </PageSection>
  );
}
