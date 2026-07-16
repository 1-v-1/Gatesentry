<script lang="ts">
  import {
    HeaderNav,
    HeaderNavItem,
    HeaderNavMenu,
  } from "carbon-components-svelte";
  import { menuItems } from "../menu";
  import { store } from "../store/apistore";
  import { afterUpdate } from "svelte";
  import { gsNavigate } from "../lib/navigate";
  import { _ } from "svelte-i18n";
  $: loggedIn = $store.api.loggedIn;

  let menuItemsToRender = [...menuItems];
  afterUpdate(() => {
    if (loggedIn) {
      menuItemsToRender = [...menuItems];
    } else {
      menuItemsToRender = [];
    }
  });
</script>

<HeaderNav>
  {#each menuItemsToRender as item}
    {#if item.type === "link"}
      <HeaderNavItem
        text={$_(item.text)}
        on:click={() => {
          gsNavigate(item.href);
        }}
      />
    {:else if item.type === "menu"}
      <HeaderNavMenu text={$_(item.text)}>
        {#each item.children as child}
          <HeaderNavItem
            text={$_(child.text)}
            on:click={() => {
              gsNavigate(child.href);
            }}
          />
        {/each}
      </HeaderNavMenu>
    {/if}
  {/each}
</HeaderNav>
