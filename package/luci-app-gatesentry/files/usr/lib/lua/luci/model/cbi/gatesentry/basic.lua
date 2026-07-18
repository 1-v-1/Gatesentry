m = Map("gatesentry", translate("GateSentry"),
	translate("GateSentry runtime parameters. Filter rules, users, blocklists and HTTPS interception remain in the web admin on port 10786 of the running service."))

-- ── Security banner ─────────────────────────────────────────────────────────
banner = m:section(SimpleSection, nil, translatef(
	"<strong>%s</strong> &mdash; %s",
	translate("Security notice"),
	translate("The default admin/admin credentials are active. Change the password in the GateSentry web admin (port 10786) before exposing this device to untrusted networks.")
))

-- ── Service section ─────────────────────────────────────────────────────────
s = m:section(TypedSection, "gatesentry", translate("Service"))
s.anonymous = true
s.addremove = false

e = s:option(Flag, "enabled", translate("Enable service"))
e.default  = e.disabled
e.rmempty  = false

http_port = s:option(Value, "http_port", translate("HTTP proxy port"))
http_port.datatype = "port"
http_port.default  = "10413"
http_port:depends("enabled", "1")

admin_port = s:option(Value, "admin_port", translate("Web admin port"))
admin_port.datatype = "port"
admin_port.default  = "10786"
admin_port:depends("enabled", "1")

tp = s:option(Value, "transparent_port", translate("Transparent proxy port"))
tp.datatype = "port"
tp.default  = "10414"
tp:depends("enabled", "1")

te = s:option(Flag, "transparent", translate("Enable transparent proxy"))
te.default = te.enabled
te:depends("enabled", "1")

socks5e = s:option(Flag, "socks5_enabled", translate("Enable SOCKS5 proxy"))
socks5e.default = socks5e.enabled
socks5e:depends("enabled", "1")

socks5p = s:option(Value, "socks5_port", translate("SOCKS5 proxy port"))
socks5p.datatype = "port"
socks5p.default  = "10415"
socks5p:depends("socks5_enabled", "1")

ba = s:option(Value, "bind_address", translate("Bind address"))
ba.datatype = "ipaddr"
ba.default  = "0.0.0.0"
ba:depends("enabled", "1")

-- ── DNS server section ───────────────────────────────────────────────────────
s2 = m:section(TypedSection, "gatesentry", translate("Built-in DNS server"))
s2.anonymous = true
s2.addremove = false

de = s2:option(Flag, "dns_enabled", translate("Enable built-in DNS server"))
de.default = de.disabled
de.description = translate("Conflicts with dnsmasq if both bind port 53. Disable on routers already running dnsmasq for LAN clients.")

dp = s2:option(Value, "dns_port", translate("DNS listen port"))
dp.datatype = "port"
dp.default  = "53"
dp:depends("dns_enabled", "1")

da = s2:option(Value, "dns_addr", translate("DNS listen address"))
da.datatype = "ipaddr"
da.default  = "0.0.0.0"
da:depends("dns_enabled", "1")

dr = s2:option(Value, "dns_resolver", translate("Upstream DNS resolver"))
dr.datatype = "host"
dr.default  = "1.1.1.1:53"
dr:depends("dns_enabled", "1")

-- ── Advanced section ─────────────────────────────────────────────────────────
s3 = m:section(TypedSection, "gatesentry", translate("Advanced"))
s3.anonymous = true
s3.addremove = false

tz = s3:option(ListValue, "tz", translate("Timezone"))
tz:value("UTC")
tz:value("Europe/Oslo")
tz:value("Europe/London")
tz:value("Europe/Berlin")
tz:value("America/New_York")
tz:value("America/Los_Angeles")
tz:value("Asia/Shanghai")
tz:value("Asia/Tokyo")
tz:value("Asia/Singapore")
tz.default = "UTC"

dbg = s3:option(Flag, "debug_logging", translate("Debug logging"))
dbg.default = dbg.disabled

ms = s3:option(Value, "max_scan_size_mb", translate("Max content scan size (MB)"))
ms.datatype = "range(1, 1000)"
ms.default  = "10"

mdns = s3:option(Flag, "mdns_browser", translate("mDNS / Bonjour browser"))
mdns.default       = mdns.disabled
mdns:depends("dns_enabled", "1")
mdns.description   = translate("Has no effect when the built-in DNS server is disabled.")

egress = s3:option(Value, "egress_socks5", translate("Egress SOCKS5 proxy"))
egress.datatype = "string"
egress.default  = ""
egress.description = translate("Routes GateSentry's own outbound HTTP (blocklist downloads, AIA cert fetches, AI scanner) through this upstream SOCKS5 proxy. Format: socks5://[user:pass@]host:port. Empty = direct.")

alo = s3:option(Flag, "admin_lan_only", translate("Restrict admin port to LAN (firewall rule)"))
alo.default = alo.enabled

-- ── Validation ──────────────────────────────────────────────────────────────
function m.on_commit(map)
	-- on_commit is invoked with only (map); pass the full cbid string to
	-- Map:formvalue. AbstractValue:formvalue(section) builds the cbid from
	-- the section name but dies when section is nil, and passing it the
	-- section name "main" hard-codes the assumption that TypedSection has
	-- a single named instance.
	local hp = map:formvalue("cbid.gatesentry.main.http_port") or "10413"
	local ap = map:formvalue("cbid.gatesentry.main.admin_port") or "10786"
	local sp = map:formvalue("cbid.gatesentry.main.socks5_port") or "10415"
	if hp == ap then
		map.proceed = false
		map.error   = "ports_clash"
		map.message = translate("HTTP proxy port and admin port must differ")
	end
	if hp == sp or ap == sp then
		map.proceed = false
		map.error   = "ports_clash"
		map.message = translate("SOCKS5 port must differ from HTTP proxy and admin ports")
	end
end

return m