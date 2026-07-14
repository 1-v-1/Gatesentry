package gatesentryWebserver

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	gatesentryFilters "bitbucket.org/abdullah_irfan/gatesentryf/filters"
	gatesentry2logger "bitbucket.org/abdullah_irfan/gatesentryf/logger"
	gatesentry2storage "bitbucket.org/abdullah_irfan/gatesentryf/storage"
	gatesentryTypes "bitbucket.org/abdullah_irfan/gatesentryf/types"
	gatesentryWebserverEndpoints "bitbucket.org/abdullah_irfan/gatesentryf/webserver/endpoints"
	gatesentryWebserverFrontend "bitbucket.org/abdullah_irfan/gatesentryf/webserver/frontend"
	gatesentryWebserverTypes "bitbucket.org/abdullah_irfan/gatesentryf/webserver/types"

	"github.com/golang-jwt/jwt/v5"

	"github.com/gorilla/mux"
)

// hmacSecret is the HS256 key used to sign and verify session JWTs. It is no
// longer hardcoded — it is generated on first start and persisted to
// <basedir>/jwt.secret with mode 0600. InitJWTSecret must be called before any
// request that may invoke CreateToken or authenticationMiddleware.
var hmacSecret []byte

const jwtSecretFileName = "jwt.secret"

// InitJWTSecret loads the HMAC signing key from <basedir>/jwt.secret. If the
// file does not exist, a fresh 32-byte cryptographically random key is
// generated, written with 0600 permissions, and held in memory. Returns an
// error only if basedir is unusable AND a generated key could not be kept
// somewhere readable — in that case callers should refuse to start.
func InitJWTSecret(basedir string) error {
	if basedir == "" {
		basedir = "."
	}
	if err := os.MkdirAll(basedir, 0o700); err != nil {
		return fmt.Errorf("cannot create basedir for jwt secret: %w", err)
	}
	path := filepath.Join(basedir, jwtSecretFileName)

	if data, err := os.ReadFile(path); err == nil {
		raw, decErr := hex.DecodeString(strings.TrimSpace(string(data)))
		if decErr == nil && len(raw) >= 32 {
			hmacSecret = raw
			log.Printf("JWT secret loaded from %s (%d bytes)", path, len(raw))
			return nil
		}
		log.Printf("JWT secret at %s is missing or invalid; regenerating", path)
	} else if !os.IsNotExist(err) {
		log.Printf("could not read %s: %v; regenerating", path, err)
	}

	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Errorf("crypto/rand failed: %w", err)
	}
	hmacSecret = buf
	encoded := hex.EncodeToString(buf) + "\n"
	if err := os.WriteFile(path, []byte(encoded), 0o600); err != nil {
		return fmt.Errorf("cannot persist jwt secret to %s: %w", path, err)
	}
	log.Printf("Generated new JWT secret and persisted to %s (mode 0600)", path)
	return nil
}

func getJWTSecret() []byte {
	if len(hmacSecret) == 0 {
		// Defensive: bail loudly rather than silently fall back to a public key.
		panic("gatesentryWebserver: JWT secret not initialized — call InitJWTSecret first")
	}
	return hmacSecret
}

// panicRecoveryMiddleware converts any panic in downstream handlers into a 500
// JSON response so clients see a stable error surface and the server log gets
// the stack instead of the net/http default (which leaks the stack to stderr
// and still keeps the goroutine dead).
var panicRecoveryMiddleware mux.MiddlewareFunc = func(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("panic recovered in %s %s: %v\n%s",
					r.Method, r.URL.Path, rec, debug.Stack())
				// Guard against partial writes — check whether the response is
				// already partially committed before writing again.
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"status":500,"message":"internal server error"}` + "\n"))
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Pass     string `json:"pass"`
}

type ErrorResponse struct {
	StatusCode   int    `json:"status"`
	ErrorMessage string `json:"message"`
}

type OkResponse struct {
	Response string `json:"Response"`
}

func CreateToken(username string) (string, error) {

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": username,
		"nbf":      time.Now().Unix(),
		"exp":      time.Now().Add(time.Hour * 1).Unix(),
	})

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString(getJWTSecret())

	return tokenString, err
}

func VerifyAdminUser(username string, password string, settingsStore *gatesentry2storage.MapStore) bool {
	if gatesentryWebserverTypes.GetAdminUser(settingsStore) == username &&
		gatesentryWebserverTypes.GetAdminPassword(settingsStore) == password {
		return true
	}
	return false
}

var tokenCreationHandler HttpHandlerFunc = func(w http.ResponseWriter, r *http.Request) {
	// get username from context
	username, ok := r.Context().Value("username").(string)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Error getting username"))
		return
	}
	token, err := CreateToken(username)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Error creating token"))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"Jwtoken": "` + token + `", "Validated": "true"}`))

}

var authenticationMiddleware mux.MiddlewareFunc = func(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		// Check if tokenString starts with "Bearer ", and if so, remove it
		if strings.HasPrefix(tokenString, "Bearer ") {
			tokenString = strings.TrimPrefix(tokenString, "Bearer ")
		}
		if tokenString == "" {
			SendError(w, errors.New("Missing token auth"), http.StatusUnauthorized)
			return
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Don't forget to validate the alg is what you expect:

			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}

			return getJWTSecret(), nil
		})
		// jwt.Parse returns (nil, err) when the token cannot be parsed at all
		// (malformed, bad signature with strict alg, alg=none, etc.). Without
		// this guard, every such request dereferences a nil *Token and panics.
		if err != nil || token == nil || !token.Valid {
			SendError(w, err, http.StatusUnauthorized)
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			SendError(w, errors.New("Invalid claims type"), http.StatusUnauthorized)
			return
		}
		// Comma-ok avoids a second class of panic: a valid signature that lacks
		// a usable username claim (interface conversion: nil).
		username, ok := claims["username"].(string)
		if !ok || username == "" {
			SendError(w, errors.New("Missing username claim"), http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "username", username)
		log.Println("Logged in with username = ", username)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

var verifyAuthHandler HttpHandlerFunc = func(w http.ResponseWriter, r *http.Request) {
	username, ok := r.Context().Value("username").(string)
	if !ok {
		SendError(w, errors.New("Error getting username"), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	SendJSON(w, struct {
		Validated bool
		Jwtoken   string
		Message   string
	}{Validated: true, Jwtoken: "", Message: `Username : ` + username})
}

var indexHandler = makeIndexHandler("/")

func makeIndexHandler(basePath string) HttpHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data := gatesentryWebserverFrontend.GetIndexHtmlWithBasePath(basePath)
		if data == nil {
			SendError(w, errors.New("Error getting index.html"), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write(data)
	}
}

func RegisterEndpointsStartServer(
	Filters *[]gatesentryFilters.GSFilter,
	runtime *gatesentryWebserverTypes.TemporaryRuntime,
	logger *gatesentry2logger.Log,
	dnsServerInfo *gatesentryTypes.DnsServerInfo,
	boundAddress *string,
	port string,
	internalSettings *gatesentry2storage.MapStore,
	ruleManager gatesentryWebserverEndpoints.RuleManagerInterface,
	basePath string,
) {

	internalServer := NewGsWeb(basePath)

	internalServer.Post("/api/auth/token", HttpHandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var data User
		if err := ParseJSONRequest(r, &data); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Error parsing json"))
			return
		}
		if !VerifyAdminUser(data.Username, data.Pass, internalSettings) {

			SendJSON(w, struct {
				Validated bool
			}{Validated: false})

			return
		}
		ctx := context.WithValue(r.Context(), "username", data.Username)
		tokenCreationHandler(w, r.WithContext(ctx))
	}))

	internalServer.Get("/api/about", HttpHandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		responseJson := gatesentryWebserverEndpoints.GSApiAboutGET(runtime)
		SendJSON(w, responseJson)
	}))

	internalServer.Get("/api/auth/verify", authenticationMiddleware, verifyAuthHandler)

	internalServer.Get("/api/filters", authenticationMiddleware, func(w http.ResponseWriter, r *http.Request) {
		responseJson := gatesentryWebserverEndpoints.GetAllFilters(Filters)
		SendJSON(w, responseJson)
	})
	internalServer.Get("/api/filters/{id}", authenticationMiddleware, func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		requestedId := vars["id"]
		responseJson := gatesentryWebserverEndpoints.GetSingleFilter(requestedId, Filters)
		SendJSON(w, responseJson)
	})
	internalServer.Post("/api/filters/{id}", authenticationMiddleware, func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		requestedId := vars["id"]
		var dataReceived []gatesentryFilters.GsFilterLine
		ParseJSONRequest(r, &dataReceived)
		responseJson := gatesentryWebserverEndpoints.PostSingleFilter(requestedId, dataReceived, Filters)
		SendJSON(w, responseJson)
		runtime.Reload()
	})

	internalServer.Get("/api/settings/{id}", authenticationMiddleware, func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		requestedId := vars["id"]
		jsonResponse := gatesentryWebserverEndpoints.GSApiSettingsGET(requestedId, internalSettings)
		SendJSON(w, jsonResponse)
	})

	internalServer.Post("/api/settings/{id}", authenticationMiddleware, func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		requestedId := vars["id"]
		var temp gatesentryWebserverTypes.Datareceiver
		err := ParseJSONRequest(r, &temp)
		if err != nil {
			SendError(w, err, http.StatusInternalServerError)
			return
		}
		output := gatesentryWebserverEndpoints.GSApiSettingsPOST(requestedId, internalSettings, temp)
		runtime.Reload()
		SendJSON(w, output)
	})

	internalServer.Get("/api/users", authenticationMiddleware, func(w http.ResponseWriter, r *http.Request) {
		jsonResponse := gatesentryWebserverEndpoints.GSApiUsersGET(runtime, internalSettings.Get("authusers"))
		SendJSON(w, jsonResponse)
	})

	internalServer.Put("/api/users", authenticationMiddleware, func(w http.ResponseWriter, r *http.Request) {
		var userJson gatesentryWebserverEndpoints.UserInputJsonSingle
		err := ParseJSONRequest(r, &userJson)
		if err != nil {
			SendError(w, err, http.StatusInternalServerError)
			return
		}
		jsonResponse := gatesentryWebserverEndpoints.GSApiUserPUT(internalSettings, userJson)
		SendJSON(w, jsonResponse)
		runtime.Reload()
	})

	internalServer.Delete("/api/users/{username}", authenticationMiddleware, func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		username := vars["username"]
		jsonResponse := gatesentryWebserverEndpoints.GSApiUserDELETE(username, internalSettings)
		SendJSON(w, jsonResponse)
		runtime.Reload()
	})

	internalServer.Post("/api/users", authenticationMiddleware, func(w http.ResponseWriter, r *http.Request) {
		var userJson gatesentryWebserverEndpoints.UserInputJsonSingle
		err := ParseJSONRequest(r, &userJson)
		if err != nil {
			SendError(w, err, http.StatusInternalServerError)
			return
		}
		jsonResponse := gatesentryWebserverEndpoints.GSApiUserCreate(userJson, internalSettings)
		SendJSON(w, jsonResponse)
		runtime.Reload()
	})

	internalServer.Get("/api/consumption", authenticationMiddleware, func(w http.ResponseWriter, r *http.Request) {
		data := string(runtime.GetUserGetJSON())
		output := gatesentryWebserverEndpoints.GSApiConsumptionGET(data, internalSettings, runtime)
		SendJSON(w, output)
	})

	internalServer.Post("/api/consumption", authenticationMiddleware, func(w http.ResponseWriter, r *http.Request) {
		var temp gatesentryWebserverEndpoints.Datareceiver
		err := ParseJSONRequest(r, &temp)
		if err != nil {
			return
		}
		output := gatesentryWebserverEndpoints.GSApiConsumptionPOST(temp, internalSettings, runtime)
		SendJSON(w, output)
	})

	internalServer.Get("/api/logs/{id}", HttpHandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queryParams := r.URL.Query()
		searchValue := queryParams.Get("search")

		if searchValue != "" {
			output := gatesentryWebserverEndpoints.ApiLogsSearchGET(logger, searchValue)
			SendJSON(w, output)
			return
		}

		output := gatesentryWebserverEndpoints.ApiLogsGET(logger)
		SendJSON(w, output)
	}))

	internalServer.Get("/api/dns/info", authenticationMiddleware, func(w http.ResponseWriter, r *http.Request) {
		output := gatesentryWebserverEndpoints.GSApiDNSInfo(dnsServerInfo)
		SendJSON(w, output)
	})

	internalServer.Get("/api/dns/custom_entries", authenticationMiddleware, func(w http.ResponseWriter, r *http.Request) {
		data := internalSettings.Get("DNS_custom_entries")
		output := gatesentryWebserverEndpoints.GSApiDNSEntriesCustom(data, internalSettings, runtime)
		SendJSON(w, output)
	})

	internalServer.Post("/api/dns/custom_entries", authenticationMiddleware, func(w http.ResponseWriter, r *http.Request) {
		var customEntries []gatesentryTypes.DNSCustomEntry
		err := ParseJSONRequest(r, &customEntries)
		if err != nil {
			SendError(w, err, http.StatusInternalServerError)
			return
		}
		output := gatesentryWebserverEndpoints.GSApiDNSSaveEntriesCustom(customEntries, internalSettings, runtime)
		SendJSON(w, output)
		runtime.Reload()
	})

	internalServer.Post("/api/stats", authenticationMiddleware, func(w http.ResponseWriter, r *http.Request) {
		params := mux.Vars(r)
		fromTimeParam := params["fromTime"]
		output := gatesentryWebserverEndpoints.ApiGetStats(fromTimeParam, logger)
		SendJSON(w, output)
	})

	internalServer.Get("/api/status", authenticationMiddleware, func(w http.ResponseWriter, r *http.Request) {
		output := gatesentryWebserverEndpoints.ApiGetStatus(logger, boundAddress)
		SendJSON(w, output)
	})

	internalServer.Get("/api/stats/byUrl", authenticationMiddleware, func(w http.ResponseWriter, r *http.Request) {
		output := gatesentryWebserverEndpoints.ApiGetStatsByURL(logger)
		SendJSON(w, output)
	})

	internalServer.Get("/api/toggleServer/{id}", authenticationMiddleware, func(w http.ResponseWriter, r *http.Request) {
		params := mux.Vars(r)
		id := params["id"]
		output := gatesentryWebserverEndpoints.ApiToggleServer(id, logger)
		SendJSON(w, output)
	})

	internalServer.Get("/api/certificate/info", authenticationMiddleware, func(w http.ResponseWriter, r *http.Request) {
		output := gatesentryWebserverEndpoints.GetCertificateInfo(internalSettings)
		SendJSON(w, output)
	})

	internalServer.Get("/api/files/certificate", HttpHandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		output := gatesentryWebserverEndpoints.GetCertificateBytes(internalSettings)
		w.Header().Set("Content-Disposition", "attachment; filename=certificate.pem")
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(output)
	}))

	// Register rule endpoints with authentication
	log.Println("Initializing rule manager...")
	gatesentryWebserverEndpoints.InitRuleManager(ruleManager)
	log.Println("Rule manager initialized")

	log.Println("Registering GET /api/rules...")
	internalServer.Get("/api/rules", authenticationMiddleware, func(w http.ResponseWriter, r *http.Request) {
		gatesentryWebserverEndpoints.GSApiRulesGetAll(w, r)
	})

	log.Println("Registering POST /api/rules...")
	internalServer.Post("/api/rules", authenticationMiddleware, func(w http.ResponseWriter, r *http.Request) {
		gatesentryWebserverEndpoints.GSApiRuleCreate(w, r)
	})

	log.Println("Registering GET /api/rules/{id}...")
	internalServer.Get("/api/rules/{id}", authenticationMiddleware, func(w http.ResponseWriter, r *http.Request) {
		gatesentryWebserverEndpoints.GSApiRuleGet(w, r)
	})

	log.Println("Registering PUT /api/rules/{id}...")
	internalServer.Put("/api/rules/{id}", authenticationMiddleware, func(w http.ResponseWriter, r *http.Request) {
		gatesentryWebserverEndpoints.GSApiRuleUpdate(w, r)
	})

	log.Println("Registering DELETE /api/rules/{id}...")
	internalServer.Delete("/api/rules/{id}", authenticationMiddleware, func(w http.ResponseWriter, r *http.Request) {
		gatesentryWebserverEndpoints.GSApiRuleDelete(w, r)
	})

	log.Println("Registering POST /api/rules/test...")
	internalServer.Post("/api/rules/test", authenticationMiddleware, func(w http.ResponseWriter, r *http.Request) {
		gatesentryWebserverEndpoints.GSApiRuleTest(w, r)
	})
	log.Println("All rule endpoints registered successfully")

	// Device inventory endpoints
	log.Println("Registering device API endpoints...")
	internalServer.Get("/api/devices", authenticationMiddleware, func(w http.ResponseWriter, r *http.Request) {
		gatesentryWebserverEndpoints.GSApiDevicesGetAll(w, r)
	})
	internalServer.Get("/api/devices/{id}", authenticationMiddleware, func(w http.ResponseWriter, r *http.Request) {
		gatesentryWebserverEndpoints.GSApiDeviceGet(w, r)
	})
	internalServer.Post("/api/devices/{id}/name", authenticationMiddleware, func(w http.ResponseWriter, r *http.Request) {
		gatesentryWebserverEndpoints.GSApiDeviceSetName(w, r)
	})
	internalServer.Delete("/api/devices/{id}", authenticationMiddleware, func(w http.ResponseWriter, r *http.Request) {
		gatesentryWebserverEndpoints.GSApiDeviceDelete(w, r)
	})
	log.Println("Device API endpoints registered")

	// Register MIME types for static file serving
	mime.AddExtensionType(".css", "text/css")
	mime.AddExtensionType(".js", "application/javascript")
	mime.AddExtensionType(".svg", "image/svg+xml")

	// Serve static assets from the embedded files/fs/ directory.
	// GetFSHandler() returns fs.Sub(build, "files"), so files live at fs/bundle.js etc.
	// We only strip the basePath prefix (not /fs), so the remaining path /fs/bundle.js
	// correctly maps to fs/bundle.js in the embedded filesystem.
	fsHandler := http.FileServer(gatesentryWebserverFrontend.GetFSHandler())
	// Wrap the file server so:
	//   1. Content-Type is set explicitly from the URL extension for known asset
	//      types, instead of relying on Go's sniffed fallback (which can return
	//      text/plain for short CSS files whose first 512 bytes do not look
	//      distinctively like CSS — browsers then refuse to apply the stylesheet).
	//   2. 404s return a small JSON body with Content-Type application/json,
	//      rather than Go's default text/plain "404 page not found", which can
	//      otherwise be misread by a strict browser as a malformed response.
	staticHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ct := mime.TypeByExtension(filepath.Ext(r.URL.Path)); ct != "" {
			w.Header().Set("Content-Type", ct)
		}
		fsHandler.ServeHTTP(w, r)
	})
	// Strip only the basePath prefix (not /fs), so the remaining path
	// /fs/style2.css maps to fs/style2.css in the embedded filesystem
	// (which is rooted at files/, i.e. files/fs/style2.css).
	// For basePath "/", TrimSuffix yields "" and StripPrefix is a no-op.
	internalServer.sub.PathPrefix("/fs/").Handler(
		http.StripPrefix(strings.TrimSuffix(basePath, "/"), staticHandler),
	)

	baseIndexHandler := makeIndexHandler(basePath)
	internalServer.Get("/", baseIndexHandler)
	internalServer.Get("/login", baseIndexHandler)
	internalServer.Get("/stats", baseIndexHandler)
	internalServer.Get("/users", baseIndexHandler)
	internalServer.Get("/dns", baseIndexHandler)
	internalServer.Get("/settings", baseIndexHandler)
	internalServer.Get("/rules", baseIndexHandler)
	internalServer.Get("/logs", baseIndexHandler)
	internalServer.Get("/blockedkeywords", baseIndexHandler)
	internalServer.Get("/blockedfiletypes", baseIndexHandler)
	internalServer.Get("/excludeurls", baseIndexHandler)
	internalServer.Get("/blockedurls", baseIndexHandler)
	internalServer.Get("/excludehosts", baseIndexHandler)
	internalServer.Get("/services", baseIndexHandler)
	internalServer.Get("/devices", baseIndexHandler)
	internalServer.Get("/ai", baseIndexHandler)

	internalServer.ListenAndServe(":" + port)

}
