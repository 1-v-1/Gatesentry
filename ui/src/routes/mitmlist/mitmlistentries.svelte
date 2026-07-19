<script lang="ts">
  import {
    Button,
    InlineLoading,
    InlineNotification,
    TextInput,
    Row,
    Column,
  } from "carbon-components-svelte";
  import Mitmlistform from "./mitmlistform.svelte";
  import { Add } from "carbon-icons-svelte";
  import { onMount } from "svelte";
  import { getBasePath } from "../../lib/navigate";
  import { _ } from "svelte-i18n";

  let entries = [];
  let loading = false;
  let error = "";
  let success = "";
  let expandedEntries = new Set();

  // Live-match tester UI state
  let testHost = "";
  let testResult = null;
  let testing = false;

  const API_BASE = getBasePath() + "/api/mitmlist";

  function toggleExpand(index) {
    if (expandedEntries.has(index)) {
      expandedEntries.delete(index);
    } else {
      expandedEntries.add(index);
    }
    expandedEntries = expandedEntries; // trigger reactivity
  }

  async function loadEntries() {
    loading = true;
    error = "";
    try {
      const token = localStorage.getItem("jwt");
      if (!token) throw new Error("Please login first to view the MITM list");
      const response = await fetch(API_BASE, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (response.status === 401) {
        throw new Error("Authentication failed. Please login again");
      }
      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(
          `Failed to load MITM list: ${response.status} - ${errorText}`,
        );
      }
      const data = await response.json();
      entries = data.entries || [];
    } catch (err) {
      error = err.message;
    } finally {
      loading = false;
    }
  }

  onMount(() => {
    loadEntries();
  });

  function newEntry() {
    const newIndex = entries.length;
    entries = [
      ...entries,
      {
        id: "",
        name: `Entry ${entries.length + 1}`,
        regex: "",
        action: "filter",
        priority: entries.length,
        enabled: true,
        description: "",
      },
    ];
    expandedEntries.add(newIndex);
    expandedEntries = expandedEntries;
  }

  async function saveEntry(e) {
    const index = e.detail;
    loading = true;
    error = "";
    success = "";
    try {
      const token = localStorage.getItem("jwt");
      const entry = entries[index];
      const url = entry.id ? `${API_BASE}/${entry.id}` : API_BASE;
      const method = entry.id ? "PUT" : "POST";
      const response = await fetch(url, {
        method,
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(entry),
      });
      if (!response.ok) {
        const errorData = await response.text();
        throw new Error(`Failed to save entry: ${errorData}`);
      }
      const saved = await response.json();
      entries[index] = saved.entry || saved;
      entries = entries; // trigger reactivity
      success = `Entry "${entry.name || `#${index + 1}`}" saved successfully!`;
      expandedEntries.delete(index);
      expandedEntries = expandedEntries;
      setTimeout(() => (success = ""), 3000);
    } catch (err) {
      error = err.message;
    } finally {
      loading = false;
    }
  }

  async function removeEntry(e) {
    const index = e.detail;
    const entry = entries[index];
    if (entry.id) {
      loading = true;
      error = "";
      success = "";
      try {
        const token = localStorage.getItem("jwt");
        const response = await fetch(`${API_BASE}/${entry.id}`, {
          method: "DELETE",
          headers: { Authorization: `Bearer ${token}` },
        });
        if (!response.ok) {
          const errorData = await response.text();
          throw new Error(`Failed to delete entry: ${errorData}`);
        }
        success = `Entry "${entry.name || `#${index + 1}`}" deleted successfully!`;
        setTimeout(() => (success = ""), 3000);
      } catch (err) {
        error = err.message;
        loading = false;
        return;
      } finally {
        loading = false;
      }
    }
    entries = entries.filter((_, i) => i !== index);
    expandedEntries.delete(index);
    expandedEntries = expandedEntries;
  }

  async function runTest() {
    if (!testHost.trim()) return;
    testing = true;
    testResult = null;
    error = "";
    try {
      const token = localStorage.getItem("jwt");
      const response = await fetch(`${API_BASE}/test`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ host: testHost.trim() }),
      });
      if (!response.ok) {
        const txt = await response.text();
        throw new Error(txt);
      }
      testResult = await response.json();
    } catch (err) {
      error = `Test failed: ${err.message}`;
    } finally {
      testing = false;
    }
  }
</script>

<Row>
  <Column>
    {#if error}
      <InlineNotification
        kind="error"
        title="Error"
        subtitle={error}
        on:close={() => (error = "")}
      />
    {/if}

    {#if success}
      <InlineNotification
        kind="success"
        title="Success"
        subtitle={success}
        on:close={() => (success = "")}
      />
    {/if}

    <!-- Live tester -->
    <div class="simple-border" style="padding: 12px; margin-bottom: 16px;">
      <div style="display: flex; gap: 10px; align-items: flex-end;">
        <div style="flex: 1;">
          <TextInput
            size="sm"
            labelText={$_("MITMList_TestHost")}
            placeholder="www.example.com"
            bind:value={testHost}
            on:keydown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                runTest();
              }
            }}
          />
        </div>
        <Button size="small" kind="secondary" on:click={runTest} disabled={testing}>
          {$_("MITMList_Test")}
        </Button>
      </div>
      {#if testing}
        <InlineLoading description="Testing..." />
      {:else if testResult}
        {#if testResult.matched}
          <div style="margin-top: 10px;">
            <strong>{$_("MITMList_Matched")}:</strong>
            <code>{testResult.entry.name}</code>
            &mdash;
            <span class="action-badge action-{testResult.entry.action}">
              {testResult.entry.action}
            </span>
            &nbsp;(priority {testResult.entry.priority})
          </div>
        {:else}
          <div style="margin-top: 10px; color: #525252;">
            <em>{$_("MITMList_NoMatch")}</em>
          </div>
        {/if}
      {/if}
    </div>

    <div style="display: flex; justify-content: flex-end; margin-bottom: 15px;">
      <Button on:click={newEntry} icon={Add} size="small">
        {$_("MITMList_AddEntry")}
      </Button>
    </div>

    {#if loading && entries.length === 0}
      <InlineLoading description="Loading MITM list..." />
    {:else}
      {#each entries as entry, index (index)}
        <Mitmlistform
          {entry}
          {index}
          expanded={expandedEntries.has(index)}
          on:toggle={() => toggleExpand(index)}
          on:remove={removeEntry}
          on:save={saveEntry}
        />
      {/each}
    {/if}
  </Column>
</Row>

<style>
  .action-badge {
    padding: 2px 8px;
    border-radius: 12px;
    font-size: 0.75rem;
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
  :global(.simple-border) {
    border: 1px solid #e0e0e0;
    border-radius: 4px;
    background-color: white;
  }
</style>
