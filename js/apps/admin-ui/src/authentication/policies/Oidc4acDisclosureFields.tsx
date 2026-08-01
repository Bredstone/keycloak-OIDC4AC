import {
  Card,
  CardBody,
  CardTitle,
  EmptyState,
  EmptyStateBody,
  Flex,
  FlexItem,
  HelperText,
  HelperTextItem,
  Label,
  List,
  ListItem,
  MenuToggle,
  Select,
  SelectList,
  SelectOption,
  Tab,
  Tabs,
  TabTitleText,
} from "@patternfly/react-core";
import { useEffect, useState } from "react";
import style from "./oidc4ac-policy.module.css";

export type Discovery = Record<string, unknown>;
export type Capability = {
  identifier: string;
  properties: string[];
  metadata: string[];
  values: Record<string, string[]>;
};

export type DisclosureField = {
  path: string;
  name: string;
  values: string[];
};

export type DisclosureMode = "default" | "requested" | "never";

export const DEFAULT_DISCLOSURE_MODE: DisclosureMode = "requested";

export const DISCLOSURE_MODE_OPTIONS: Array<{
  value: DisclosureMode;
  label: string;
  description: string;
}> = [
  {
    value: "default",
    label: "By default",
    description: "Include when no field-specific request is present.",
  },
  {
    value: "requested",
    label: "Only when requested",
    description: "Include only when the client asks for this field.",
  },
  {
    value: "never",
    label: "Never",
    description: "Do not disclose, including for essential requests.",
  },
];

const asStrings = (value: unknown): string[] =>
  Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string")
    : [];

export const capabilitiesFromDiscovery = (discovery: Discovery): Capability[] =>
  asStrings(discovery.amr_identifiers_supported).map((identifier) => {
    const properties = asStrings(
      discovery[`${identifier}_properties_supported`],
    );
    const metadata = asStrings(discovery[`${identifier}_metadata_supported`]);
    const values = Object.fromEntries(
      properties.map((property) => [
        property,
        asStrings(discovery[`${property}_values_supported`]),
      ]),
    );
    return { identifier, properties, metadata, values };
  });

const metadataFieldsFor = (capabilities: Capability[]): DisclosureField[] => {
  const names = new Set(
    capabilities.flatMap((capability) => capability.metadata),
  );
  return [...names]
    .filter((name) => name !== "time")
    .map((name) => ({
      path: `amr_metadata.${name}`,
      name,
      values: [],
    }));
};

const propertyFieldsFor = (capability: Capability): DisclosureField[] =>
  capability.properties.map((name) => ({
    path: `amr_properties.${name}`,
    name,
    values: capability.values[name],
  }));

export const disclosureModesFromCapabilities = (
  capabilities: Capability[],
  mode: DisclosureMode = DEFAULT_DISCLOSURE_MODE,
): Record<string, DisclosureMode> =>
  Object.fromEntries(
    capabilities.flatMap((capability) => [
      ...capability.metadata
        .filter((name) => name !== "time")
        .map((name) => [`amr_metadata.${name}`, mode] as const),
      ...capability.properties.map(
        (name) => [`amr_properties.${name}`, mode] as const,
      ),
    ]),
  );

const FieldList = ({
  fields,
  modes,
  fallbackMode,
  onModeChange,
  disabled,
  idPrefix,
  capability,
}: {
  fields: DisclosureField[];
  modes: Record<string, DisclosureMode>;
  fallbackMode: DisclosureMode;
  onModeChange: (path: string, mode: DisclosureMode) => void;
  disabled: boolean;
  idPrefix: string;
  capability: string;
}) => {
  const [open, setOpen] = useState<string>();

  return (
    <List isPlain isBordered className="pf-v5-u-mt-md">
      {fields.map((field) => {
        const selected = modes[field.path] ?? fallbackMode;
        return (
          <ListItem key={field.path}>
            <Flex
              alignItems={{ default: "alignItemsCenter" }}
              spaceItems={{ default: "spaceItemsMd" }}
            >
              <FlexItem flex={{ default: "flex_1" }}>
                <code className={style.fieldName}>{field.path}</code>
                {field.values.length > 0 && (
                  <span className="pf-v5-u-ml-sm">
                    {field.values.map((value) => (
                      <Label
                        key={value}
                        isCompact
                        color="blue"
                        className="pf-v5-u-mr-xs"
                      >
                        {value}
                      </Label>
                    ))}
                  </span>
                )}
              </FlexItem>
              <FlexItem>
                <Select
                  id={`${idPrefix}-${capability}-${field.name}`}
                  isOpen={open === field.path}
                  popperProps={{
                    appendTo: document.body,
                    maxWidth: "calc(100vw - 2rem)",
                    position: "end",
                    preventOverflow: true,
                  }}
                  onOpenChange={(isOpen) =>
                    setOpen(isOpen ? field.path : undefined)
                  }
                  selected={selected}
                  onSelect={(_, value) => {
                    onModeChange(field.path, value as DisclosureMode);
                    setOpen(undefined);
                  }}
                  toggle={(ref) => (
                    <MenuToggle
                      ref={ref}
                      isExpanded={open === field.path}
                      isDisabled={disabled}
                      onClick={() =>
                        setOpen(open === field.path ? undefined : field.path)
                      }
                    >
                      {DISCLOSURE_MODE_OPTIONS.find(
                        (option) => option.value === selected,
                      )?.label ?? selected}
                    </MenuToggle>
                  )}
                >
                  <SelectList>
                    {DISCLOSURE_MODE_OPTIONS.map((option) => (
                      <SelectOption
                        key={option.value}
                        value={option.value}
                        isSelected={selected === option.value}
                        description={option.description}
                      >
                        {option.label}
                      </SelectOption>
                    ))}
                  </SelectList>
                </Select>
              </FlexItem>
            </Flex>
          </ListItem>
        );
      })}
    </List>
  );
};

export function DisclosureFields({
  capabilities,
  modes,
  fallbackMode,
  onModeChange,
  disabled,
  isDisabled = false,
  idPrefix,
}: {
  capabilities: Capability[];
  modes: Record<string, DisclosureMode>;
  fallbackMode: DisclosureMode;
  onModeChange: (path: string, mode: DisclosureMode) => void;
  disabled: boolean;
  isDisabled?: boolean;
  idPrefix: string;
}) {
  const [active, setActive] = useState(capabilities[0]?.identifier || "");
  const fieldsDisabled = disabled || isDisabled;

  useEffect(() => {
    if (!capabilities.some((capability) => capability.identifier === active)) {
      setActive(capabilities[0]?.identifier || "");
    }
  }, [active, capabilities]);

  if (capabilities.length === 0) {
    return (
      <EmptyState variant="xs">
        <EmptyStateBody>
          No authentication-method capabilities were advertised by this Keycloak
          instance.
        </EmptyStateBody>
      </EmptyState>
    );
  }

  const metadataFields = metadataFieldsFor(capabilities);

  return (
    <>
      <Card>
        <CardTitle>Optional metadata</CardTitle>
        <CardBody>
          <p className="pf-v5-u-mb-md">
            Metadata describes the authentication event and applies to every
            authentication method. The mandatory <code>amr_metadata.time</code>{" "}
            value is always retained.
          </p>
          <p className="pf-v5-u-mb-md">
            For each optional field, choose whether it is disclosed by default,
            only when requested, or never.
          </p>
          <HelperText>
            <HelperTextItem>
              <strong>amr_identifier</strong> and{" "}
              <strong>amr_metadata.time</strong> are always preserved and are
              not configurable here.
            </HelperTextItem>
          </HelperText>
          {metadataFields.length > 0 ? (
            <FieldList
              fields={metadataFields}
              modes={modes}
              fallbackMode={fallbackMode}
              onModeChange={onModeChange}
              disabled={fieldsDisabled}
              idPrefix={idPrefix}
              capability="metadata"
            />
          ) : (
            <p className="pf-v5-u-mt-md">
              No optional metadata was advertised.
            </p>
          )}
        </CardBody>
      </Card>
      <Card className="pf-v5-u-mt-md">
        <CardTitle>Authentication method properties</CardTitle>
        <CardBody>
          <p className="pf-v5-u-mb-md">
            Properties describe the method or credential used for each
            execution. Select a method to configure its optional properties.
            Each field can be disclosed by default, only when requested, or
            never.
          </p>
          <Tabs
            activeKey={active}
            onSelect={(_, key) => setActive(key as string)}
            mountOnEnter
            unmountOnExit
          >
            {capabilities.map((capability) => {
              const propertyFields = propertyFieldsFor(capability);
              return (
                <Tab
                  key={capability.identifier}
                  eventKey={capability.identifier}
                  id={`${idPrefix}-${capability.identifier}`}
                  title={<TabTitleText>{capability.identifier}</TabTitleText>}
                >
                  <div className="pf-v5-u-pt-md">
                    <p className="pf-v5-u-mb-md">
                      Select optional properties that may be disclosed for{" "}
                      <strong>{capability.identifier}</strong>. Enumerated
                      values are shown beside each property.
                    </p>
                    {propertyFields.length > 0 ? (
                      <FieldList
                        fields={propertyFields}
                        modes={modes}
                        fallbackMode={fallbackMode}
                        onModeChange={onModeChange}
                        disabled={fieldsDisabled}
                        idPrefix={idPrefix}
                        capability={capability.identifier}
                      />
                    ) : (
                      <p>This method has no optional properties advertised.</p>
                    )}
                  </div>
                </Tab>
              );
            })}
          </Tabs>
        </CardBody>
      </Card>
    </>
  );
}
