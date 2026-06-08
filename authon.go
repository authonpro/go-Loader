// ╔══════════════════════════════════════════════════════════════════════════════╗
// ║  Authon Go SDK — Software Licensing & Authentication                       ║
// ║  Version: 1.0.0                                                            ║
// ║  Standard library only (no external dependencies)                          ║
// ║                                                                            ║
// ║  Website: https://authon.pro                                               ║
// ║  Docs:    https://authon.pro/docs                                          ║
// ║  Discord: https://discord.gg/jMZCTKPsmE                                    ║
// ║  Status:  https://authon.pro/status                                        ║
// ║  Health:  https://api.authon.pro/health                                    ║
// ║  GitHub:  https://github.com/authonpro                                     ║
// ║                                                                            ║
// ║  Usage:                                                                    ║
// ║    client := authon.New("app-id", "api-key")                               ║
// ║    if err := client.Init(); err != nil { log.Fatal(err) }                  ║
// ║    resp, err := client.Login("user", "pass", "")                           ║
// ║    if err != nil { log.Fatal(err) }                                        ║
// ║    fmt.Println("Welcome!", resp.Username)                                  ║
// ╚══════════════════════════════════════════════════════════════════════════════╝

package authon

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

const (
	// Version is the SDK version string.
	Version = "1.0.0"

	// DefaultAPIURL is the default Authon API endpoint.
	DefaultAPIURL = "https://api.authon.pro/v1"

	// DefaultTimeout is the default HTTP request timeout.
	DefaultTimeout = 15 * time.Second
)

// ═══════════════════════════════════════════════════════════════════════════════
// ERROR TYPES
// ═══════════════════════════════════════════════════════════════════════════════

// AuthonError represents an error returned by the Authon API.
type AuthonError struct {
	Message string
	Code    int
}

func (e *AuthonError) Error() string {
	if e.Code != 0 {
		return fmt.Sprintf("authon: %s (code %d)", e.Message, e.Code)
	}
	return fmt.Sprintf("authon: %s", e.Message)
}

// ═══════════════════════════════════════════════════════════════════════════════
// DATA TYPES
// ═══════════════════════════════════════════════════════════════════════════════

// Response represents a generic API response.
type Response struct {
	Success bool                   `json:"success"`
	Message string                 `json:"message,omitempty"`
	Data    map[string]interface{} `json:"data,omitempty"`
}

// SessionData holds the authenticated session information.
type SessionData struct {
	SessionToken string `json:"sessionToken"`
	Username     string `json:"username"`
	Level        int    `json:"level"`
	Subscription string `json:"subscription"`
	ExpiresAt    string `json:"expiresAt"`
}

// AppInfo holds the application information returned from Init().
type AppInfo struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	HwidLock  bool   `json:"hwidLock"`
	HashCheck bool   `json:"hashCheck"`
}

// FileInfo represents a downloadable file entry.
type FileInfo struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Size     int64  `json:"size"`
	MinLevel int    `json:"minLevel"`
}

// OnlineData represents online users information.
type OnlineData struct {
	Count int      `json:"count"`
	Users []string `json:"users"`
}

// StatsData represents application statistics.
type StatsData struct {
	TotalUsers  int    `json:"totalUsers"`
	OnlineUsers int    `json:"onlineUsers"`
	TotalKeys   int    `json:"totalKeys"`
	AppVersion  string `json:"appVersion"`
}

// BlacklistData represents blacklist check results.
type BlacklistData struct {
	Blacklisted bool   `json:"blacklisted"`
	Reason      string `json:"reason"`
}

// ReferralData represents referral redemption results.
type ReferralData struct {
	ExpiresAt  string `json:"expiresAt"`
	RewardDays int    `json:"rewardDays"`
}

// ═══════════════════════════════════════════════════════════════════════════════
// CLIENT
// ═══════════════════════════════════════════════════════════════════════════════

// Client is the main Authon SDK client.
// Create one using New() and call Init() before using other methods.
type Client struct {
	// Configuration
	appID  string
	apiKey string
	apiURL string
	client *http.Client

	// Session state (populated after login/license)
	SessionToken string
	Username     string
	Level        int
	Subscription string
	ExpiresAt    string

	// App info (populated after Init)
	AppName    string
	AppVersion string
	HwidLock   bool
	HashCheck  bool

	// Internal state
	initialized bool
}

// New creates a new Authon client.
//
// Parameters:
//   - appID:  Your Application ID from the Authon dashboard.
//   - apiKey: Your API Key from the Authon dashboard.
//
// Returns a configured client ready for Init().
func New(appID, apiKey string) *Client {
	return &Client{
		appID:  appID,
		apiKey: apiKey,
		apiURL: DefaultAPIURL,
		client: &http.Client{Timeout: DefaultTimeout},
	}
}

// NewWithURL creates a new Authon client with a custom API URL.
func NewWithURL(appID, apiKey, apiURL string) *Client {
	c := New(appID, apiKey)
	if apiURL != "" {
		c.apiURL = strings.TrimRight(apiURL, "/")
	}
	return c
}

// IsAuthenticated returns true if the client has an active session token.
func (c *Client) IsAuthenticated() bool {
	return c.SessionToken != ""
}

// ═══════════════════════════════════════════════════════════════════════════════
// HWID GENERATION
// ═══════════════════════════════════════════════════════════════════════════════

// GetHWID generates a hardware ID unique to the current machine.
//
// On Windows: Uses disk serial number + computer name.
// On Linux:   Uses /etc/machine-id.
// On macOS:   Uses system_profiler hardware UUID.
//
// Returns a 32-character lowercase hexadecimal MD5 hash.
func GetHWID() string {
	var raw string

	switch runtime.GOOS {
	case "windows":
		// Get disk serial via wmic
		out, err := exec.Command("wmic", "diskdrive", "get", "serialnumber").Output()
		if err == nil {
			lines := strings.Split(string(out), "\n")
			if len(lines) > 1 {
				raw = strings.TrimSpace(lines[1])
			}
		}
		hostname, _ := os.Hostname()
		raw += hostname

	case "darwin":
		// macOS hardware UUID
		out, err := exec.Command("system_profiler", "SPHardwareDataType").Output()
		if err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				if strings.Contains(line, "UUID") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						raw = strings.TrimSpace(parts[1])
						break
					}
				}
			}
		}
		if raw == "" {
			hostname, _ := os.Hostname()
			raw = hostname
		}

	default:
		// Linux: machine-id
		data, err := os.ReadFile("/etc/machine-id")
		if err == nil {
			raw = strings.TrimSpace(string(data))
		} else {
			hostname, _ := os.Hostname()
			raw = hostname + runtime.GOARCH
		}
	}

	if raw == "" {
		hostname, _ := os.Hostname()
		raw = hostname + "fallback"
	}

	hash := md5.Sum([]byte(raw))
	return hex.EncodeToString(hash[:])
}

// ═══════════════════════════════════════════════════════════════════════════════
// INTERNAL HTTP
// ═══════════════════════════════════════════════════════════════════════════════

// request sends a POST request to the Authon API.
func (c *Client) request(payload map[string]interface{}) ([]byte, error) {
	payload["appId"] = c.appID
	payload["apiKey"] = c.apiKey

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("authon: failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", c.apiURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("authon: failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Authon-Go-SDK/"+Version)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, &AuthonError{Message: "Connection failed. Check your internet or API status at https://authon.pro/status"}
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}

// requestJSON sends a request and parses the JSON response.
func (c *Client) requestJSON(payload map[string]interface{}) (*Response, error) {
	data, err := c.request(payload)
	if err != nil {
		return nil, err
	}

	var result Response
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, &AuthonError{Message: "Invalid response from server"}
	}

	return &result, nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// INITIALIZATION
// ═══════════════════════════════════════════════════════════════════════════════

// Init initializes the connection to the Authon API and validates credentials.
// Must be called before any other API method.
//
// On success, populates AppName, AppVersion, HwidLock, and HashCheck.
//
// Returns an error if the connection fails or credentials are invalid.
func (c *Client) Init() error {
	resp, err := c.requestJSON(map[string]interface{}{
		"type": "init",
	})
	if err != nil {
		return err
	}

	if !resp.Success {
		return &AuthonError{Message: resp.Message}
	}

	if resp.Data != nil {
		if v, ok := resp.Data["name"].(string); ok {
			c.AppName = v
		}
		if v, ok := resp.Data["version"].(string); ok {
			c.AppVersion = v
		}
		if v, ok := resp.Data["hwidLock"].(bool); ok {
			c.HwidLock = v
		}
		if v, ok := resp.Data["hashCheck"].(bool); ok {
			c.HashCheck = v
		}
	}

	c.initialized = true
	return nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// AUTHENTICATION
// ═══════════════════════════════════════════════════════════════════════════════

// Login authenticates with username and password.
//
// Parameters:
//   - username: The user's username.
//   - password: The user's password.
//   - hwid:     Hardware ID (pass "" to auto-generate).
//
// On success, populates SessionToken, Username, Level, Subscription, ExpiresAt.
//
// Possible error messages:
//   - "Invalid credentials"
//   - "Account banned"
//   - "Hardware ID mismatch"
//   - "Subscription expired"
//   - "Account is frozen"
//   - "VPN/Proxy connections are not allowed"
func (c *Client) Login(username, password, hwid string) (*SessionData, error) {
	if username == "" || password == "" {
		return nil, errors.New("authon: username and password are required")
	}

	if hwid == "" {
		hwid = GetHWID()
	}

	resp, err := c.requestJSON(map[string]interface{}{
		"type":     "login",
		"username": username,
		"password": password,
		"hwid":     hwid,
	})
	if err != nil {
		return nil, err
	}

	if !resp.Success {
		return nil, &AuthonError{Message: resp.Message}
	}

	session := c.extractSession(resp.Data)
	c.SessionToken = session.SessionToken
	c.Username = session.Username
	c.Level = session.Level
	c.Subscription = session.Subscription
	c.ExpiresAt = session.ExpiresAt

	return session, nil
}

// License authenticates using a license key only (no username/password).
//
// Parameters:
//   - licenseKey: The license key to validate/activate.
//   - hwid:       Hardware ID (pass "" to auto-generate).
//
// On success, populates session state properties.
//
// Possible error messages:
//   - "Invalid or already used license key"
//   - "Hardware ID mismatch"
func (c *Client) License(licenseKey, hwid string) (*SessionData, error) {
	if licenseKey == "" {
		return nil, errors.New("authon: license key is required")
	}

	if hwid == "" {
		hwid = GetHWID()
	}

	resp, err := c.requestJSON(map[string]interface{}{
		"type":       "license",
		"licenseKey": licenseKey,
		"hwid":       hwid,
	})
	if err != nil {
		return nil, err
	}

	if !resp.Success {
		return nil, &AuthonError{Message: resp.Message}
	}

	session := c.extractSession(resp.Data)
	c.SessionToken = session.SessionToken
	c.Username = session.Username
	c.Level = session.Level
	c.Subscription = session.Subscription
	c.ExpiresAt = session.ExpiresAt

	return session, nil
}

// Register creates a new user account with a license key.
//
// Parameters:
//   - username:   Desired username.
//   - password:   Desired password.
//   - licenseKey: A valid, unused license key.
//   - hwid:       Hardware ID (pass "" to auto-generate).
//
// Possible error messages:
//   - "Username already exists"
//   - "Invalid or already used license key"
func (c *Client) Register(username, password, licenseKey, hwid string) error {
	if username == "" || password == "" || licenseKey == "" {
		return errors.New("authon: username, password, and licenseKey are required")
	}

	if hwid == "" {
		hwid = GetHWID()
	}

	resp, err := c.requestJSON(map[string]interface{}{
		"type":       "register",
		"username":   username,
		"password":   password,
		"licenseKey": licenseKey,
		"hwid":       hwid,
	})
	if err != nil {
		return err
	}

	if !resp.Success {
		return &AuthonError{Message: resp.Message}
	}

	return nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// SESSION MANAGEMENT
// ═══════════════════════════════════════════════════════════════════════════════

// Check validates the current session token (heartbeat).
// Returns true if the session is still valid.
func (c *Client) Check() (bool, error) {
	if c.SessionToken == "" {
		return false, errors.New("authon: no active session")
	}

	resp, err := c.requestJSON(map[string]interface{}{
		"type":         "check",
		"sessionToken": c.SessionToken,
	})
	if err != nil {
		return false, err
	}

	return resp.Success, nil
}

// Logout ends the current session and clears local state.
func (c *Client) Logout() error {
	if c.SessionToken == "" {
		return errors.New("authon: no active session")
	}

	resp, err := c.requestJSON(map[string]interface{}{
		"type":         "logout",
		"sessionToken": c.SessionToken,
	})
	if err != nil {
		return err
	}

	if resp.Success {
		c.SessionToken = ""
		c.Username = ""
		c.Level = 0
		c.Subscription = ""
		c.ExpiresAt = ""
	}

	return nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// VARIABLES
// ═══════════════════════════════════════════════════════════════════════════════

// GetVar retrieves an application-level variable (shared across all users).
//
// Parameters:
//   - key: Variable name.
//
// Returns the variable value or an error.
func (c *Client) GetVar(key string) (string, error) {
	if key == "" {
		return "", errors.New("authon: key is required")
	}

	resp, err := c.requestJSON(map[string]interface{}{
		"type":         "var",
		"key":          key,
		"sessionToken": c.SessionToken,
	})
	if err != nil {
		return "", err
	}

	if !resp.Success {
		return "", &AuthonError{Message: resp.Message}
	}

	if v, ok := resp.Data["value"].(string); ok {
		return v, nil
	}
	return "", nil
}

// SetVar sets a user-level variable (stored per authenticated user).
//
// Parameters:
//   - key:   Variable name.
//   - value: Variable value.
func (c *Client) SetVar(key, value string) error {
	if key == "" {
		return errors.New("authon: key is required")
	}

	resp, err := c.requestJSON(map[string]interface{}{
		"type":         "setvar",
		"key":          key,
		"value":        value,
		"sessionToken": c.SessionToken,
	})
	if err != nil {
		return err
	}

	if !resp.Success {
		return &AuthonError{Message: resp.Message}
	}
	return nil
}

// GetUserVar retrieves a user-level variable.
//
// Parameters:
//   - key: Variable name.
//
// Returns the variable value or an error.
func (c *Client) GetUserVar(key string) (string, error) {
	if key == "" {
		return "", errors.New("authon: key is required")
	}

	resp, err := c.requestJSON(map[string]interface{}{
		"type":         "getvar",
		"key":          key,
		"sessionToken": c.SessionToken,
	})
	if err != nil {
		return "", err
	}

	if !resp.Success {
		return "", &AuthonError{Message: resp.Message}
	}

	if v, ok := resp.Data["value"].(string); ok {
		return v, nil
	}
	return "", nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// FILES
// ═══════════════════════════════════════════════════════════════════════════════

// ListFiles returns all files available to the authenticated user.
func (c *Client) ListFiles() ([]FileInfo, error) {
	if c.SessionToken == "" {
		return nil, errors.New("authon: no active session")
	}

	data, err := c.request(map[string]interface{}{
		"type":         "list_files",
		"appId":        c.appID,
		"apiKey":       c.apiKey,
		"sessionToken": c.SessionToken,
	})
	if err != nil {
		return nil, err
	}

	var raw struct {
		Success bool       `json:"success"`
		Message string     `json:"message"`
		Data    []FileInfo `json:"data"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, &AuthonError{Message: "Invalid response from server"}
	}

	if !raw.Success {
		return nil, &AuthonError{Message: raw.Message}
	}

	return raw.Data, nil
}

// DownloadFile downloads a file by its ID and returns the raw bytes.
//
// Parameters:
//   - fileId: The file ID from ListFiles().
//
// Returns the file content as bytes.
func (c *Client) DownloadFile(fileId string) ([]byte, error) {
	if c.SessionToken == "" {
		return nil, errors.New("authon: no active session")
	}
	if fileId == "" {
		return nil, errors.New("authon: fileId is required")
	}

	payload := map[string]interface{}{
		"type":         "file",
		"appId":        c.appID,
		"apiKey":       c.apiKey,
		"fileId":       fileId,
		"sessionToken": c.SessionToken,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", c.apiURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Authon-Go-SDK/"+Version)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, &AuthonError{Message: "Connection failed"}
	}
	defer resp.Body.Close()

	ct := resp.Header.Get("Content-Type")
	if strings.Contains(ct, "octet-stream") {
		return io.ReadAll(resp.Body)
	}

	// Try GET fallback
	getURL := fmt.Sprintf("%s/files/download/%s?token=%s", c.apiURL, fileId, c.SessionToken)
	getResp, err := c.client.Get(getURL)
	if err != nil {
		return nil, err
	}
	defer getResp.Body.Close()

	if strings.Contains(getResp.Header.Get("Content-Type"), "octet-stream") {
		return io.ReadAll(getResp.Body)
	}

	return nil, &AuthonError{Message: "File download failed"}
}

// ═══════════════════════════════════════════════════════════════════════════════
// LOGGING & ANALYTICS
// ═══════════════════════════════════════════════════════════════════════════════

// Log sends an activity log message to the Authon dashboard.
//
// Parameters:
//   - message: Log message (max 500 characters).
func (c *Client) Log(message string) error {
	if len(message) > 500 {
		message = message[:500]
	}

	resp, err := c.requestJSON(map[string]interface{}{
		"type":         "log",
		"message":      message,
		"sessionToken": c.SessionToken,
	})
	if err != nil {
		return err
	}

	if !resp.Success {
		return &AuthonError{Message: resp.Message}
	}
	return nil
}

// FetchOnline returns the list of currently online users.
func (c *Client) FetchOnline() (*OnlineData, error) {
	if c.SessionToken == "" {
		return nil, errors.New("authon: no active session")
	}

	data, err := c.request(map[string]interface{}{
		"type":         "fetch_online",
		"appId":        c.appID,
		"apiKey":       c.apiKey,
		"sessionToken": c.SessionToken,
	})
	if err != nil {
		return nil, err
	}

	var raw struct {
		Success bool `json:"success"`
		Data    struct {
			Count int      `json:"count"`
			Users []string `json:"users"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, &AuthonError{Message: "Invalid response"}
	}

	return &OnlineData{
		Count: raw.Data.Count,
		Users: raw.Data.Users,
	}, nil
}

// FetchStats returns application statistics.
func (c *Client) FetchStats() (*StatsData, error) {
	if c.SessionToken == "" {
		return nil, errors.New("authon: no active session")
	}

	data, err := c.request(map[string]interface{}{
		"type":         "fetch_stats",
		"appId":        c.appID,
		"apiKey":       c.apiKey,
		"sessionToken": c.SessionToken,
	})
	if err != nil {
		return nil, err
	}

	var raw struct {
		Success bool      `json:"success"`
		Data    StatsData `json:"data"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, &AuthonError{Message: "Invalid response"}
	}

	return &raw.Data, nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECURITY
// ═══════════════════════════════════════════════════════════════════════════════

// CheckBlacklist checks if an IP address or HWID is blacklisted.
//
// Parameters:
//   - ip:   IP address to check (pass "" to skip).
//   - hwid: Hardware ID to check (pass "" to skip).
func (c *Client) CheckBlacklist(ip, hwid string) (*BlacklistData, error) {
	payload := map[string]interface{}{
		"type": "check_blacklist",
	}
	if ip != "" {
		payload["ip"] = ip
	}
	if hwid != "" {
		payload["hwid"] = hwid
	}

	resp, err := c.requestJSON(payload)
	if err != nil {
		return nil, err
	}

	if !resp.Success {
		return nil, &AuthonError{Message: resp.Message}
	}

	result := &BlacklistData{}
	if v, ok := resp.Data["blacklisted"].(bool); ok {
		result.Blacklisted = v
	}
	if v, ok := resp.Data["reason"].(string); ok {
		result.Reason = v
	}
	return result, nil
}

// RedeemReferral redeems a referral code for bonus subscription days.
//
// Parameters:
//   - code: The referral code.
//
// Returns referral data with ExpiresAt and RewardDays.
func (c *Client) RedeemReferral(code string) (*ReferralData, error) {
	if code == "" {
		return nil, errors.New("authon: referral code is required")
	}
	if c.SessionToken == "" {
		return nil, errors.New("authon: no active session")
	}

	resp, err := c.requestJSON(map[string]interface{}{
		"type":         "redeem_referral",
		"code":         code,
		"sessionToken": c.SessionToken,
	})
	if err != nil {
		return nil, err
	}

	if !resp.Success {
		return nil, &AuthonError{Message: resp.Message}
	}

	result := &ReferralData{}
	if v, ok := resp.Data["expiresAt"].(string); ok {
		result.ExpiresAt = v
	}
	if v, ok := resp.Data["rewardDays"].(float64); ok {
		result.RewardDays = int(v)
	}
	return result, nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// INTERNAL HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

// extractSession parses session data from a response data map.
func (c *Client) extractSession(data map[string]interface{}) *SessionData {
	session := &SessionData{}
	if data == nil {
		return session
	}

	if v, ok := data["sessionToken"].(string); ok {
		session.SessionToken = v
	}
	if v, ok := data["username"].(string); ok {
		session.Username = v
	}
	if v, ok := data["level"].(float64); ok {
		session.Level = int(v)
	}
	if v, ok := data["subscription"].(string); ok {
		session.Subscription = v
	}
	if v, ok := data["expiresAt"].(string); ok {
		session.ExpiresAt = v
	}
	return session
}
