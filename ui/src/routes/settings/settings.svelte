<script lang="ts">
  import { _ } from "svelte-i18n";
  import { Button, ButtonSet, InlineNotification } from "carbon-components-svelte";

  import ConnectedGeneralSettingInput from "../../components/connectedGeneralSettingInputs.svelte";
  import HttpsToggle from "../../components/httpsToggle.svelte";
  import ConnectedCertificateComposed from "../../components/connectedCertificateComposed.svelte";
  import ConnectedSettingInput from "../../components/connectedSettingInput.svelte";
  import ConnectedBlockPageInput from "../../components/connectedBlockPageInput.svelte";
  import { Breadcrumb, BreadcrumbItem } from "carbon-components-svelte";
  import { store } from "../../store/apistore";
  import { notificationstore } from "../../store/notifications";
  import { createNotificationSuccess, createNotificationError } from "../../lib/utils";
  import { onMount } from "svelte";

  let certInfo: any = null;
  let regenerating = false;

  const loadCertInfo = () => {
    $store.api.doCall("/certificate/info").then((json) => {
      certInfo = json;
    });
  };

  const regenerateCertificate = async () => {
    if (!confirm($_("Regenerate the CA certificate? Clients that trusted the old CA must reinstall the new one."))) {
      return;
    }
    regenerating = true;
    try {
      await $store.api.doCall("/certificate/regenerate", "post");
      loadCertInfo();
      notificationstore.add(
        createNotificationSuccess(
          {
            title: $_("Success"),
            subtitle: $_("Certificate regenerated. Restart GateSentry to pick it up."),
          },
          $_,
        ),
      );
    } catch (e) {
      notificationstore.add(
        createNotificationError(
          {
            title: $_("Failed to regenerate"),
            subtitle: String(e),
          },
          $_,
        ),
      );
    } finally {
      regenerating = false;
    }
  };

  onMount(loadCertInfo);
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

<h3 style="margin-top: 24px;">{$_("CA Certificate")}</h3>
<p style="font-size: 0.85rem; color: #525252; max-width: 720px;">
  {$_(
    "GateSentry uses a self-signed root CA to sign per-host certificates during HTTPS interception. Regenerate to roll the key (e.g. after a suspected compromise). Existing clients will need to install the new CA.",
  )}
</p>
{#if certInfo && !certInfo.error}
  <div style="font-size: 0.85rem; color: #525252; margin: 8px 0;">
    <div><strong>{$_("Subject")}:</strong> {certInfo.subject}</div>
    <div><strong>{$_("Issued")}:</strong> {certInfo.not_before}</div>
    <div><strong>{$_("Expires")}:</strong> {certInfo.not_after} ({certInfo.days_to_expiry} {$_("days")})</div>
    <div><strong>{$_("Serial")}:</strong> {certInfo.serial}</div>
  </div>
{/if}
<ButtonSet>
  <Button kind="danger" on:click={regenerateCertificate} disabled={regenerating}>
    {regenerating ? $_("Regenerating...") : $_("Regenerate CA certificate")}
  </Button>
</ButtonSet>
<br />

<ConnectedSettingInput
  keyName="egress_socks5"
  title={$_("Egress SOCKS5 Proxy")}
  labelText={$_("Egress SOCKS5 proxy URL")}
  helperText={$_("Routes GateSentry's own outbound HTTP (blocklist downloads, AIA cert fetches, AI scanner) through this upstream SOCKS5 proxy. Format: socks5://[user:pass@]host:port. Empty = direct egress.")}
  type="text"
/>
<br />

<h3 style="margin-top: 24px;">{$_("Block Page")}</h3>
<p style="font-size: 0.85rem; color: #525252; max-width: 720px;">
  {$_(
    "Customize the page users see when a request is blocked by the proxy. Empty value restores the default Gatesentry block page.",
  )}
</p>
<ConnectedBlockPageInput />
