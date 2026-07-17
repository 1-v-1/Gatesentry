package gatesentryf

import (
	"fmt"
	"net"
	"strconv"
	"time"

	gatesentry2storage "bitbucket.org/abdullah_irfan/gatesentryf/storage"
	gatesentryWebserver "bitbucket.org/abdullah_irfan/gatesentryf/webserver"
	gatesentryWebserverTypes "bitbucket.org/abdullah_irfan/gatesentryf/webserver/types"
)

func GSwebserverStart(port int) {

	GSWebServerPort := port
	ggport := strconv.Itoa(GSWebServerPort)
	t := time.NewTicker(time.Second * 10)
	portavailable := false
	for {
		fmt.Println("Checking if port is available")
		ln, err := net.Listen("tcp", ":"+ggport)
		if err != nil {
			fmt.Println("Port is not open for webserver")
		} else {
			portavailable = true
			err = ln.Close()
		}

		if portavailable {
			break
		}
		<-t.C
	}

	basePath := GetBasePath()
	fmt.Println("Webserver is listening on : " + ggport + " (base path: " + basePath + ")")
	gatesentry2storage.SetBaseDir(GSBASEDIR)
	// Initialize the JWT signing secret before any auth middleware can run.
	// Fails fast if we cannot persist the secret — better than silently
	// shipping JWTs that anyone could forge because the key is well-known.
	if err := gatesentryWebserver.InitJWTSecret(GSBASEDIR); err != nil {
		fmt.Println("Failed to initialize JWT secret:", err)
		return
	}
	R.GSWebSettings = gatesentry2storage.NewMapStore("GSWebSettings", true)

	runtimeArgs := gatesentryWebserverTypes.InputArgs{
		GetUserGetJSON:          R.GSUserGetDataJSON,
		AuthUsers:               R.AuthUsers,
		RemoveUser:              R.RemoveUser,
		UpdateUser:              R.UpdateUser,
		GetInstallationId:       R.GetInstallationId,
		GetTotalConsumptionData: R.GetTotalConsumptionData,
		GetApplicationVersion:   R.GetApplicationVersion,
		Reload:                  R.Init,
		ReloadBlockPage:         R.ReloadBlockPage,
	}
	runtime := gatesentryWebserverTypes.NewTemporaryRuntime(runtimeArgs)

	// gatesentryWebserver.RegisterEndpoints(app, settings, &R.Filters, R.Logger, runtime, R.BoundAddress)

	gatesentryWebserver.RegisterEndpointsStartServer(
		&R.Filters,
		runtime,
		R.Logger,
		R.DnsServerInfo,
		R.BoundAddress,
		strconv.Itoa(GSWebServerPort),
		R.GSSettings,
		NewRuleManager(R.GSSettings),
		basePath,
	)

	// app.Listen(":" + strconv.Itoa(GSWebServerPort))
}
