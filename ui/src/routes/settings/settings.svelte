<script lang="ts">
  import { _ } from "svelte-i18n";

  import ConnectedGeneralSettingInput from "../../components/connectedGeneralSettingInputs.svelte";
  import HttpsToggle from "../../components/httpsToggle.svelte";
  import ConnectedCertificateComposed from "../../components/connectedCertificateComposed.svelte";
  import ConnectedSettingInput from "../../components/connectedSettingInput.svelte";
  import ConnectedBlockPageInput from "../../components/connectedBlockPageInput.svelte";
  import { Breadcrumb, BreadcrumbItem } from "carbon-components-svelte";
</script>

<Breadcrumb style="margin-bottom: 10px;">
  <BreadcrumbItem href="/">Dashboard</BreadcrumbItem>
  <BreadcrumbItem>Settings</BreadcrumbItem>
</Breadcrumb>

<h2>Settings</h2>

<br />

<ConnectedGeneralSettingInput
  keyName="log_location"
  title={$_("Log Location")}
  labelText={$_("Log Location")}
  type="text"
  helperText=""
/>
<br />
<ConnectedGeneralSettingInput
  keyName="admin_username"
  helperText={""}
  type="text"
  title={$_("Admin username")}
  labelText={$_("Admin username")}
  disabled={true}
/>

<HttpsToggle />

<ConnectedCertificateComposed />

<h3 style="margin-top: 24px;">{$_("Block Page")}</h3>
<p style="font-size: 0.85rem; color: #525252; max-width: 720px;">
  {$_(
    "Customize the page users see when a request is blocked by the proxy. Empty value restores the default Gatesentry block page.",
  )}
</p>
<ConnectedBlockPageInput />
