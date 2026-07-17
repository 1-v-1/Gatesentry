<script lang="ts">
  import { Button, InlineNotification, TextArea } from "carbon-components-svelte";
  import { _ } from "svelte-i18n";
  import { onDestroy, onMount } from "svelte";

  import { store } from "../store/apistore";
  import { notificationstore } from "../store/notifications";
  import {
    createNotificationError,
    createNotificationSuccess,
  } from "../lib/utils";

  // Sentinel mirrored from the backend (handler_settings.go).
  const SIZE_CAP_BYTES = 256 * 1024;
  const TOO_LARGE_SENTINEL = "ERROR_BLOCK_PAGE_HTML_TOO_LARGE";

  // State
  let savedValue = "";
  let internalValue = "";
  let loaded = false;
  let saving = false;
  let resetting = false;
  let showPreview = false;

  // Reactive helpers
  $: isDirty = internalValue !== savedValue;
  $: bytes = new Blob([internalValue]).size;
  $: overCap = bytes > SIZE_CAP_BYTES;

  const loadAPIData = async () => {
    try {
      const json = await $store.api.getSetting("block_page_html");
      savedValue = json.Value ?? "";
      internalValue = savedValue;
    } catch (error) {
      console.error(
        "[GatesentryUI] Unable to load block_page_html (possibly due to logout)",
      );
    } finally {
      loaded = true;
    }
  };

  const onSave = async () => {
    if (saving) return;
    saving = true;
    try {
      const response = await $store.api.setSetting(
        "block_page_html",
        internalValue,
      );
      // The backend echoes the TOO_LARGE_SENTINEL string when the payload
      // exceeds the size cap. setSetting's mapper callback gets the raw
      // Datareceiver back, so we check by re-reading the current value.
      // (setSetting itself resolves to true on any 2xx; we detect the
      // size-cap error via a follow-up read.)
      // Simpler: ask the API to echo back; if response carries the sentinel
      // in any well-defined form, surface an error.
      // setSetting currently resolves `true` regardless of the response
      // body's sentinel — so we check explicitly.
      const echo = await $store.api.getSetting("block_page_html");
      const body = (response && (response.Value || response.value)) || "";
      const errored =
        body === TOO_LARGE_SENTINEL ||
        (typeof response === "string" && response === TOO_LARGE_SENTINEL);
      if (errored) {
        notificationstore.add(
          createNotificationError(
            { subtitle: $_("Block page HTML exceeds the 256 KB size limit.") },
            $_,
          ),
        );
        return;
      }
      // Sync our local savedValue to whatever the server now reports.
      savedValue = echo.Value ?? "";
      internalValue = savedValue;
      notificationstore.add(
        createNotificationSuccess(
          { subtitle: $_("Setting updated") },
          $_,
        ),
      );
    } catch (error) {
      console.error("[GatesentryUI] Failed to save block page HTML:", error);
      notificationstore.add(
        createNotificationError(
          { subtitle: $_("Unable to save setting") },
          $_,
        ),
      );
    } finally {
      saving = false;
    }
  };

  const onReset = async () => {
    if (resetting) return;
    resetting = true;
    try {
      await $store.api.setSetting("block_page_html", "");
      savedValue = "";
      internalValue = "";
      notificationstore.add(
        createNotificationSuccess(
          { subtitle: $_("Setting updated") },
          $_,
        ),
      );
    } catch (error) {
      console.error("[GatesentryUI] Failed to reset block page HTML:", error);
      notificationstore.add(
        createNotificationError(
          { subtitle: $_("Unable to save setting") },
          $_,
        ),
      );
    } finally {
      resetting = false;
    }
  };

  // Mirror the Go injectKeywordBlock helper so the preview is faithful.
  // Used only to render the "With score & reasons" preview pane.
  const escapeHTML = (s: string): string =>
    s.replace(/[&<>"']/g, (c) =>
      c === "&"
        ? "&amp;"
        : c === "<"
        ? "&lt;"
        : c === ">"
        ? "&gt;"
        : c === '"'
        ? "&quot;"
        : "&#39;",
    );

  const injectForPreview = (
    html: string,
    reasons: string[],
    score: number,
  ): string => {
    const block =
      `<div id="gs-keyword-extra">` +
      `<p>The page you requested has been blocked because it generated a score of <u>${escapeHTML(
        String(score),
      )}</u> which is above the viewing limits on this network.</p>` +
      `<p>Reason(s) this page was blocked was presence of the following:</p><ul>` +
      reasons
        .map((r) => `<li><strong>${escapeHTML(r)}</strong></li>`)
        .join("") +
      `</ul></div>`;

    const SENTINEL = "<!--GS_REASONS-->";
    if (html.includes(SENTINEL)) {
      return html.replace(SENTINEL, block);
    }
    const lower = html.toLowerCase();
    const bodyIdx = lower.lastIndexOf("</body>");
    if (bodyIdx >= 0) {
      return html.slice(0, bodyIdx) + block + html.slice(bodyIdx);
    }
    const htmlIdx = lower.lastIndexOf("</html>");
    if (htmlIdx >= 0) {
      return html.slice(0, htmlIdx) + block + html.slice(htmlIdx);
    }
    return html + block;
  };

  const SAMPLE_REASONS = ["violence", "drugs"];
  const SAMPLE_SCORE = 42;

  $: previewSrc = internalValue;
  $: withScoreSrc = injectForPreview(internalValue, SAMPLE_REASONS, SAMPLE_SCORE);

  onMount(async () => {
    await loadAPIData();
  });

  onDestroy(() => {
    savedValue = "";
    internalValue = "";
    loaded = false;
  });
</script>

{#if loaded}
  <div class="bx--form-item">
    <label class="bx--label" for="block-page-html-textarea">
      {$_("Custom HTML")}
      {#if isDirty}<span style="color: #da1e28;">*</span>{/if}
    </label>
    <div style="font-size: 0.75rem; color: #525252; margin-bottom: 4px;">
      {$_(
        "Customize the page users see when a request is blocked. Empty value restores the default Gatesentry block page.",
      )}
    </div>

    <TextArea
      id="block-page-html-textarea"
      bind:value={internalValue}
      rows={20}
      placeholder={`<html>
  <body>
    <h1>Blocked</h1>
    <p>This site is not allowed on this network.</p>
    <!--GS_REASONS-->
  </body>
</html>`}
      style="font-family: 'IBM Plex Mono', 'Menlo', monospace; font-size: 0.8rem;"
    />

    <div
      style="display: flex; justify-content: space-between; align-items: center; margin-top: 6px; font-size: 0.75rem;"
    >
      <div style="color: #525252;">
        {$_("Size: ")} {bytes.toLocaleString()} / {SIZE_CAP_BYTES.toLocaleString()} {$_("bytes")}
      </div>
      <div>
        <Button
          kind="ghost"
          size="small"
          icon={showPreview ? undefined : undefined}
          on:click={() => (showPreview = !showPreview)}
        >
          {showPreview ? $_("Hide preview") : $_("Preview")}
        </Button>
        <Button
          kind="ghost"
          size="small"
          disabled={resetting || !internalValue}
          on:click={onReset}
        >
          {$_("Reset to default")}
        </Button>
        <Button
          size="small"
          disabled={saving || !isDirty || overCap}
          on:click={onSave}
        >
          {saving ? $_("Saving...") : $_("Save")}
        </Button>
      </div>
    </div>

    {#if overCap}
      <InlineNotification
        kind="error"
        title={$_("Block page HTML is too large")}
        subtitle={$_("Maximum size: 256 KB. Trim your HTML before saving.")}
        hideCloseButton
      />
    {/if}

    {#if isDirty && !overCap}
      <InlineNotification
        kind="warning"
        title={$_("Unsaved changes")}
        subtitle={$_("Click Save to apply the new block page.")}
        hideCloseButton
      />
    {/if}

    <details style="margin-top: 8px; font-size: 0.75rem; color: #525252;">
      <summary style="cursor: pointer;">{$_("Tips")}</summary>
      <ul style="margin-top: 4px; padding-left: 18px;">
        <li>
          {$_(
            'Optional: insert <!--GS_REASONS--> in your HTML to control where the matched keywords list appears. Without it the block is injected before </body>.',
          )}
        </li>
        <li>
          {$_(
            "Maximum size: 256 KB. Image blocks (transparent PNG) are not affected by this setting.",
          )}
        </li>
        <li>
          {$_(
            "Inline your assets — external <script src> and <link href> references may be blocked by the browser's same-origin policy.",
          )}
        </li>
      </ul>
    </details>

    {#if showPreview}
      <div style="margin-top: 12px;">
        <div style="font-size: 0.85rem; font-weight: 600; margin-bottom: 4px;">
          {$_("Preview (as served on a non-keyword block)")}
        </div>
        <iframe
          title="block-page-preview"
          sandbox=""
          srcdoc={previewSrc}
          style="width: 100%; height: 260px; border: 1px solid #c6c6c6; background: #fff;"
        ></iframe>

        <div style="font-size: 0.85rem; font-weight: 600; margin: 12px 0 4px;">
          {$_("With score & reasons (as served on a keyword block)")}
        </div>
        <iframe
          title="block-page-preview-with-score"
          sandbox=""
          srcdoc={withScoreSrc}
          style="width: 100%; height: 320px; border: 1px solid #c6c6c6; background: #fff;"
        ></iframe>
      </div>
    {/if}
  </div>
{/if}