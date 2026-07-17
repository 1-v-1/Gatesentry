package gatesentry2responder

import (
	"strings"
	"testing"
)

func TestInjectKeywordBlock_Sentinel(t *testing.T) {
	in := `<html><body><h1>Blocked</h1><!--GS_REASONS--></body></html>`
	out := injectKeywordBlock(in, []string{"drugs", "violence"}, 42)
	if !strings.Contains(out, "<u>42</u>") {
		t.Fatalf("expected score 42 in output, got: %s", out)
	}
	if !strings.Contains(out, "<li><strong>drugs</strong></li>") {
		t.Fatalf("expected reasons list, got: %s", out)
	}
	if !strings.Contains(out, `<li><strong>violence</strong></li>`) {
		t.Fatalf("expected violence reason, got: %s", out)
	}
	// Sentinel should be replaced (no occurrence left in output).
	if strings.Contains(out, "<!--GS_REASONS-->") {
		t.Fatalf("sentinel should be replaced, got: %s", out)
	}
}

func TestInjectKeywordBlock_BodyFallback(t *testing.T) {
	in := `<html><body><h1>Blocked</h1></body></html>`
	out := injectKeywordBlock(in, []string{"x"}, 5)
	// Block must be injected just before </body>.
	want := `<div id="gs-keyword-extra">`
	idxBlock := strings.Index(out, want)
	idxBody := strings.Index(out, "</body>")
	if idxBlock < 0 || idxBody < 0 || idxBlock > idxBody {
		t.Fatalf("expected block before </body>, got: %s", out)
	}
}

func TestInjectKeywordBlock_CaseInsensitiveBody(t *testing.T) {
	in := `<HTML><BODY><h1>Blocked</h1></BODY></HTML>`
	out := injectKeywordBlock(in, []string{"x"}, 1)
	if strings.Contains(out, "<!--GS_REASONS-->") {
		t.Fatalf("sentinel should not be present")
	}
	if !strings.Contains(out, `id="gs-keyword-extra"`) {
		t.Fatalf("expected keyword block, got: %s", out)
	}
}

func TestInjectKeywordBlock_NoBodyFallback(t *testing.T) {
	in := `<h1>Blocked</h1>` // no body, no html
	out := injectKeywordBlock(in, []string{"x"}, 1)
	if !strings.HasSuffix(out, `</ul></div>`) {
		t.Fatalf("expected block appended at end, got: %s", out)
	}
}

func TestInjectKeywordBlock_HTMLEscapesReasons(t *testing.T) {
	in := `<html><body><!--GS_REASONS--></body></html>`
	// Inject a reason with HTML chars; we expect them escaped, not raw.
	out := injectKeywordBlock(in, []string{`<script>alert(1)</script>`}, 7)
	if strings.Contains(out, "<script>alert(1)</script>") {
		t.Fatalf("reasons must be HTML-escaped, got: %s", out)
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Fatalf("expected escaped tags, got: %s", out)
	}
}

func TestBuildResponsePage_EmptyCustomReturnsLegacyDefault(t *testing.T) {
	// Empty customHTML must not change behavior — legacy default still served.
	out := BuildResponsePage([]string{"drugs"}, 99, "")
	if !strings.Contains(out, "GateSentry Web Filter") {
		t.Fatalf("expected legacy default block page, got: %s", out[:200])
	}
	if !strings.Contains(out, "<u>99</u>") {
		t.Fatalf("expected score 99 in default page, got: %s", out)
	}
}

func TestBuildResponsePage_CustomHTMLUsed(t *testing.T) {
	custom := `<html><body><h1>Custom</h1><!--GS_REASONS--></body></html>`
	out := BuildResponsePage([]string{"x"}, 1, custom)
	if !strings.Contains(out, "<h1>Custom</h1>") {
		t.Fatalf("expected custom HTML served, got: %s", out)
	}
	if !strings.Contains(out, "id=\"gs-keyword-extra\"") {
		t.Fatalf("expected keyword block injected, got: %s", out)
	}
	if strings.Contains(out, "GateSentry Web Filter") {
		t.Fatalf("default page must not appear when customHTML is set, got: %s", out)
	}
}

func TestBuildGeneralResponsePage_CustomHTMLUsed(t *testing.T) {
	custom := `<html><body><h1>Custom</h1></body></html>`
	out := BuildGeneralResponsePage([]string{"x"}, -1, custom)
	if out != custom {
		t.Fatalf("general page must return customHTML verbatim, got: %s", out)
	}
}