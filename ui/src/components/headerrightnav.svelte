<script lang="ts">
  import { store } from "../store/apistore";
  import { _, locale } from "svelte-i18n";
  import { setLocale, SUPPORTED_LOCALES } from "../language/i18n";

  export let userProfilePanelOpen;
  import {
    Button,
    Checkbox,
    ComposedModal,
    HeaderAction,
    HeaderGlobalAction,
    HeaderPanelDivider,
    HeaderPanelLink,
    HeaderPanelLinks,
    HeaderUtilities,
    ModalBody,
    ModalFooter,
    ModalHeader,
  } from "carbon-components-svelte";
  import {
    Language,
    SettingsAdjust,
    UserAvatarFilledAlt,
  } from "carbon-icons-svelte";
  import { afterUpdate } from "svelte";
  import ConnectedGeneralSettingInputs from "./connectedGeneralSettingInputs.svelte";
  import { gsNavigate } from "../lib/navigate";

  $: loggedIn = $store.api.loggedIn;
  let checked = false;
  let languagePanelOpen = false;

  let bindedUpdate;
  let modalOpen;

  let onLogout = () => {
    // navigate("/login");
    store.logout();
    userProfilePanelOpen = false;
    modalOpen = false;
    gsNavigate("/login");
  };
</script>

<HeaderUtilities>
  <HeaderAction
    bind:isOpen={languagePanelOpen}
    icon={Language}
    closeIcon={Language}
  >
    <HeaderPanelLinks>
      <HeaderPanelDivider>{$_("Language")}</HeaderPanelDivider>
      {#each SUPPORTED_LOCALES as l}
        <HeaderPanelLink
          on:click={() => {
            setLocale(l.code);
            languagePanelOpen = false;
          }}
        >
          {l.label}{$locale === l.code ? " ✓" : ""}
        </HeaderPanelLink>
      {/each}
    </HeaderPanelLinks>
  </HeaderAction>

  {#if loggedIn}
    <HeaderAction
      bind:isOpen={userProfilePanelOpen}
      icon={UserAvatarFilledAlt}
      closeIcon={UserAvatarFilledAlt}
    >
      <HeaderPanelLinks>
        <HeaderPanelDivider>{$_("Logged in as admin")}</HeaderPanelDivider>
        <HeaderPanelLink
          on:click={() => {
            modalOpen = true;
          }}>{$_("Change password")}</HeaderPanelLink
        >
        <HeaderPanelLink on:click={onLogout}>{$_("Logout")}</HeaderPanelLink>
      </HeaderPanelLinks>
    </HeaderAction>

    <ComposedModal open={modalOpen}>
      <ModalHeader title={$_("Update password")} />

      <ModalBody hasForm>
        {#if loggedIn}
          <ConnectedGeneralSettingInputs
            keyName="admin_password"
            helperText={$_("Leave blank to keep the current password")}
            type="password"
            title={$_("Password")}
            labelText={$_("Password")}
            disableOnblur={true}
            bind:updateDataOnBackend={bindedUpdate}
          />
        {/if}
      </ModalBody>
      <ModalFooter
        secondaryButtonText={$_("Proceed")}
        primaryButtonDisabled={true}
        secondaryClass="button--primary"
        on:click:button--secondary={() => {
          modalOpen = false;
          bindedUpdate();
        }}
      />
    </ComposedModal>
  {/if}
</HeaderUtilities>
