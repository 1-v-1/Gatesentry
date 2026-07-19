<script lang="ts">
  import {
    Button,
    Dropdown,
    NumberInput,
    Tag,
    TextArea,
    TextInput,
    Toggle,
  } from "carbon-components-svelte";
  import { _ } from "svelte-i18n";
  import { ChevronDown, ChevronUp, RowDelete } from "carbon-icons-svelte";
  import { createEventDispatcher } from "svelte";

  export let entry = {
    id: "",
    name: "",
    regex: "",
    action: "filter",
    priority: 0,
    enabled: true,
    description: "",
  };

  export let index;
  export let expanded = false;

  const dispatch = createEventDispatcher();

  function toggleExpand() {
    dispatch("toggle");
  }
</script>

<div class="simple-border">
  {#if !expanded}
    <div class="entry-summary" on:click={toggleExpand}>
      <div class="summary-content">
        <div class="summary-left">
          <span class="entry-number">#{index + 1}</span>
          <strong>{entry.name || `Entry ${index + 1}`}</strong>
          {#if entry.regex}
            <code class="regex-cell">{entry.regex}</code>
          {/if}
        </div>
        <div class="summary-right">
          <span class="action-badge action-{entry.action}">{entry.action}</span>
          <span class="priority-badge">p={entry.priority}</span>
          {#if !entry.enabled}
            <Tag size="sm" type="gray">disabled</Tag>
          {/if}
          <Button
            size="small"
            kind="ghost"
            icon={ChevronDown}
            iconDescription="Expand"
          />
        </div>
      </div>
    </div>
  {:else}
    <div class="entry-header" on:click={toggleExpand}>
      <h5>{$_("MITMList_Entry")} {index + 1}</h5>
      <Button
        size="small"
        kind="ghost"
        icon={ChevronUp}
        iconDescription="Collapse"
      />
    </div>

    <div class="entry-form">
      <table class="entry-table">
        <tbody>
          <tr>
            <td class="label-col">{$_("MITMList_Enabled")}</td>
            <td class="input-col">
              <Toggle
                size="sm"
                bind:toggled={entry.enabled}
                hideLabel
                labelA=""
                labelB=""
              />
            </td>
          </tr>

          <tr>
            <td class="label-col">{$_("MITMList_Name")}</td>
            <td class="input-col">
              <TextInput
                size="sm"
                type="text"
                bind:value={entry.name}
                placeholder="GitHub passthrough"
              />
            </td>
          </tr>

          <tr>
            <td class="label-col">{$_("MITMList_Regex")} *</td>
            <td class="input-col">
              <TextInput
                size="sm"
                type="text"
                bind:value={entry.regex}
                placeholder=".*\.example\.com"
                helperText={$_("MITMList_RegexHelp")}
              />
            </td>
          </tr>

          <tr>
            <td class="label-col">{$_("MITMList_Action")}</td>
            <td class="input-col">
              <Dropdown
                size="sm"
                selectedId={entry.action}
                on:select={(e) => {
                  entry.action = e.detail.selectedId;
                }}
                items={[
                  { id: "filter", text: $_("MITMList_ActionFilter") },
                  { id: "passthrough", text: $_("MITMList_ActionPassthrough") },
                  { id: "blackhole", text: $_("MITMList_ActionBlackhole") },
                ]}
              />
            </td>
          </tr>

          <tr>
            <td class="label-col">{$_("MITMList_Priority")}</td>
            <td class="input-col">
              <NumberInput
                size="sm"
                bind:value={entry.priority}
                helperText={$_("MITMList_PriorityHelp")}
              />
            </td>
          </tr>

          <tr>
            <td class="label-col">{$_("MITMList_Description")}</td>
            <td class="input-col">
              <TextArea
                rows={2}
                bind:value={entry.description}
                placeholder={$_("MITMList_DescriptionPlaceholder")}
              />
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <div class="entry-footer">
      <Button
        size="small"
        icon={RowDelete}
        kind="danger-tertiary"
        on:click={() => dispatch("remove", index)}
      >
        {$_("MITMList_RemoveEntry")}
      </Button>
      <Button
        size="small"
        kind="primary"
        on:click={() => dispatch("save", index)}
      >
        {$_("MITMList_SaveEntry")}
      </Button>
    </div>
  {/if}
</div>

<style>
  .entry-summary {
    padding: 15px;
    cursor: pointer;
    display: flex;
    align-items: center;
    transition: background-color 0.2s;
  }
  .entry-summary:hover {
    background-color: #f4f4f4;
  }
  .summary-content {
    display: flex;
    width: 100%;
    justify-content: space-between;
    align-items: center;
  }
  .summary-left {
    display: flex;
    align-items: center;
    gap: 15px;
    min-width: 0;
  }
  .summary-right {
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .entry-number {
    color: #525252;
    font-weight: 500;
  }
  .regex-cell {
    font-family: monospace;
    background-color: #f4f4f4;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 0.85rem;
    max-width: 280px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .action-badge {
    padding: 4px 12px;
    border-radius: 12px;
    font-size: 0.875rem;
    font-weight: 500;
    text-transform: uppercase;
  }
  .action-filter {
    background-color: #d0e2ff;
    color: #0043ce;
  }
  .action-passthrough {
    background-color: #defbe6;
    color: #0e6027;
  }
  .action-blackhole {
    background-color: #ffd7d9;
    color: #a2191f;
  }
  .priority-badge {
    background-color: #e0e0e0;
    padding: 4px 10px;
    border-radius: 12px;
    font-size: 0.75rem;
    color: #161616;
  }
  .entry-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 12px 15px;
    cursor: pointer;
    border-bottom: 1px solid #e0e0e0;
    background-color: #f4f4f4;
  }
  .entry-header:hover {
    background-color: #e8e8e8;
  }
  .entry-form {
    padding: 15px;
  }
  .entry-table {
    width: 100%;
    border-collapse: collapse;
  }
  .entry-table td {
    padding: 8px 10px;
    vertical-align: top;
  }
  .label-col {
    width: 160px;
    font-weight: 500;
    color: #161616;
    padding-top: 12px;
  }
  .input-col {
    padding-left: 20px;
  }
  .entry-footer {
    display: flex;
    justify-content: space-between;
    padding: 10px 15px;
    border-top: 1px solid #e0e0e0;
    background-color: #f4f4f4;
  }
  .simple-border {
    border: 1px solid #e0e0e0;
    margin-bottom: 10px;
    border-radius: 4px;
    background-color: white;
  }
</style>
