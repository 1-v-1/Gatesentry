<script lang="ts">
  import { Breadcrumb, BreadcrumbItem } from "carbon-components-svelte";
  import Mitmlistentries from "./mitmlistentries.svelte";
  import { _ } from "svelte-i18n";
</script>

<Breadcrumb style="margin-bottom: 10px;">
  <BreadcrumbItem href="/">Dashboard</BreadcrumbItem>
  <BreadcrumbItem>{$_("MITMList_Title")}</BreadcrumbItem>
</Breadcrumb>
<h2>{$_("MITMList_Title")}</h2>
<p style="margin-bottom: 12px; color: #525252;">
  {$_("MITMList_Description")}
</p>
<Mitmlistentries />
