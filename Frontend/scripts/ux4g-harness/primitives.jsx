/** Isolated browser fixture. Never imported into application routes/bundles. */
import React, { useState } from "react";
import { createRoot } from "react-dom/client";
import {
  CcureAlert,
  CcureBadge,
  CcureBreadcrumb,
  CcureButton,
  CcureCard,
  CcureCheckbox,
  CcureCombobox,
  CcureDrawer,
  CcureDropdown,
  CcureIconButton,
  CcureInput,
  CcureLoader,
  CcureMenuItem,
  CcureModal,
  CcurePagination,
  CcureRadio,
  CcureSelect,
  CcureSkeleton,
  CcureSwitch,
  CcureTable,
  CcureTabPanel,
  CcureTabs,
  CcureTextarea,
  CcureToastProvider,
  useCcureToast,
  useCcureTabs,
} from "../../src/design-system";
import "./primitives.css";

function Fixture() {
  const [modal, setModal] = useState(false);
  const [drawer, setDrawer] = useState(false);
  const [menu, setMenu] = useState(false);
  const [choice, setChoice] = useState("");
  const [page, setPage] = useState(1);
  const tabs = useCcureTabs("one");
  const toast = useCcureToast();
  return (
    <main className="fixture">
      <h1>UX4G adapter validation</h1>
      <CcureBreadcrumb
        items={[{ label: "Home", href: "/" }, { label: "Primitives" }]}
      />
      <CcureCard
        title="Shared controls"
        subtitle="Official UX4G classes; React interactions"
      >
        <div className="fixture-grid">
          <CcureInput
            label="Name"
            hint="Enter a display name"
            defaultValue="CCure"
          />
          <CcureInput
            label="Invalid value"
            error="This field needs review"
            defaultValue="Invalid"
          />
          <CcureInput
            label="Disabled value"
            disabled
            defaultValue="Unavailable"
          />
          <CcureTextarea
            label="Notes"
            hint="Describe the change"
            defaultValue="Review the shared shell"
          />
          <CcureSelect label="Native theme" defaultValue="light">
            <option value="light">Light</option>
            <option value="dark">Dark</option>
          </CcureSelect>
          <CcureCombobox
            label="Searchable theme"
            name="theme"
            value={choice}
            onChange={setChoice}
            options={[
              { value: "light", label: "Light" },
              { value: "disabled", label: "Disabled", disabled: true },
              { value: "dark", label: "Dark" },
            ]}
          />
        </div>
        <div className="fixture-row">
          <CcureCheckbox>Receive updates</CcureCheckbox>
          <CcureCheckbox disabled>Unavailable option</CcureCheckbox>
          <CcureSwitch>Email alerts</CcureSwitch>
        </div>
        <fieldset>
          <legend>Display mode</legend>
          <CcureRadio name="display" value="standard" defaultChecked>
            Standard
          </CcureRadio>
          <CcureRadio name="display" value="compact">
            Compact
          </CcureRadio>
        </fieldset>
        <div className="fixture-row">
          <CcureButton>Primary action</CcureButton>
          <CcureButton variant="secondary">Secondary action</CcureButton>
          <CcureButton variant="ghost">Text action</CcureButton>
          <CcureButton variant="danger">Destructive action</CcureButton>
          <CcureButton loading>Loading action</CcureButton>
          <CcureIconButton label="Favorite">☆</CcureIconButton>
          <CcureDropdown
            open={menu}
            onOpenChange={setMenu}
            label="Actions"
            trigger={({ ref, buttonProps }) => (
              <CcureButton ref={ref} {...buttonProps}>
                Open menu
              </CcureButton>
            )}
          >
            <CcureMenuItem>First action</CcureMenuItem>
            <CcureMenuItem disabled>Disabled action</CcureMenuItem>
            <CcureMenuItem>Last action</CcureMenuItem>
          </CcureDropdown>
          <CcureButton onClick={() => setModal(true)}>Open modal</CcureButton>
          <CcureButton onClick={() => setDrawer(true)}>Open drawer</CcureButton>
          <CcureButton onClick={() => toast.success("Preferences saved")}>
            Show notification
          </CcureButton>
        </div>
      </CcureCard>
      <CcureAlert title="Information">Shared feedback</CcureAlert>
      <CcureAlert variant="danger" title="Error" live={false}>
        Check the form values
      </CcureAlert>
      <div className="fixture-row">
        <CcureBadge variant="success">Active</CcureBadge>
        <CcureBadge variant="warning">Pending</CcureBadge>
        <CcureLoader inline />
        <CcureSkeleton width="8rem" />
      </div>
      <CcureTabs
        label="Views"
        tabs={[
          { id: "one", label: "Overview" },
          { id: "two", label: "Details" },
          { id: "three", label: "Unavailable", disabled: true },
        ]}
        {...tabs.listProps}
      />
      <CcureTabPanel {...tabs.panelProps("one")}>
        Overview content
      </CcureTabPanel>
      <CcureTabPanel {...tabs.panelProps("two")}>Detail content</CcureTabPanel>
      <CcureTable
        caption="Sample records"
        columns={[
          { key: "name", header: "Name", isRowHeader: true },
          { key: "status", header: "Status" },
        ]}
        rows={[{ name: "CCure", status: "Active" }]}
      />
      <CcurePagination
        page={page}
        pageSize={10}
        total={30}
        onPageChange={setPage}
      />
      <CcureModal
        open={modal}
        onClose={() => setModal(false)}
        title="Review changes"
        footer={<CcureButton onClick={() => setModal(false)}>Done</CcureButton>}
      >
        <CcureInput label="Modal name" />
        <CcureButton onClick={() => setDrawer(true)}>
          Open nested drawer
        </CcureButton>
      </CcureModal>
      <CcureDrawer
        open={drawer}
        onClose={() => setDrawer(false)}
        title="Preferences"
      >
        <CcureSwitch>Drawer alerts</CcureSwitch>
        <CcureInput label="Drawer name" />
      </CcureDrawer>
    </main>
  );
}
const theme = new URLSearchParams(location.search).get("theme") || "light";
document.documentElement.dataset.theme = theme;
createRoot(document.getElementById("root")).render(
  <CcureToastProvider>
    <Fixture />
  </CcureToastProvider>,
);
