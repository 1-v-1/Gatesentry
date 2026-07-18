module("luci.controller.gatesentry", package.seeall)

function index()
	if not nixio.fs.access("/etc/config/gatesentry") then
		return
	end

	entry({"admin", "services", "gatesentry"}, cbi("gatesentry/basic"), _("GateSentry"), 60).dependent = true
	entry({"admin", "services", "gatesentry", "status"}, call("action_status")).leaf = true
	entry({"admin", "services", "gatesentry", "service"}, call("action_service")).leaf = true
end

function action_status()
	local sys = require("luci.sys")
	local uci = require("luci.model.uci").cursor()

	local enabled = uci:get("gatesentry", "main", "enabled") or "0"
	local running = (sys.call("pidof gatesentry-bin >/dev/null 2>&1") == 0)

	local ports = {}
	for _, p in ipairs({10413, 10414, 10415, 10786}) do
		local listening = (sys.call("ss -ltn 'sport = :%d' 2>/dev/null | grep -q LISTEN" % p) == 0)
		table.insert(ports, { port = p, listening = listening })
	end

	luci.http.prepare_content("application/json")
	luci.http.write_json({
		enabled  = enabled,
		running  = running,
		version  = sys.exec("cat /var/lib/gatesentry/gatesentry/version 2>/dev/null"):gsub("%s+", ""),
		ports    = ports,
	})
end

function action_service()
	local sys = require("luci.sys")
	local action = luci.http.formvalue("action")
	if action == "start" or action == "stop" or action == "restart" then
		sys.call("/etc/init.d/gatesentry " .. action .. " >/dev/null 2>&1")
		luci.http.status(200)
		luci.http.prepare_content("text/plain")
		luci.http.write("ok")
		return
	end
	luci.http.status(400)
	luci.http.prepare_content("text/plain")
	luci.http.write("invalid action")
end