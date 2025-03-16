package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

// AuthRequest represents the authentication payload
type AuthRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	ClientID string `json:"client_id"`
	// GrantType    string `json:"grant_type"`
	// Scope        string `json:"scope"`
	ClientSecret string `json:"client_secret"`
}

// AuthResponse represents the authentication response
type AuthResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"` // Expiration time in seconds
}

// TokenManager manages authentication tokens
type TokenManager struct {
	Username     string
	Password     string
	AuthURL      string
	Token        string
	ExpiryTime   time.Time
	ClientID     string
	GrantType    string
	Scope        string
	ClientSecret string
}

// Config struct to hold all configuration values
type Config struct {
	ServerURL  string `json:"serverURL"`
	AuthURL    string `json:"authURL"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	ApiBaseURL string `json:"apiBaseURL"`
	Query      string `json:"query"`
	ClientID   string `json:"client_id"`
	// GrantType    string `json:"grant_type"`
	// Scope        string `json:"scope"`
	ClientSecret    string  `json:"client_secret"`
	MessageInterval float64 `json:"messageinterval"`
}

type WebSocketMessage struct {
	Type   string `json:"type"`
	Stream string `json:"stream"`
}

// Function to load configuration from a JSON file
func LoadConfig(filename string) (*Config, error) {
	file, err := os.Open(filename)
	if err != nil {
		logError("Failed to open config file: %v", err)
		return nil, err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	var config Config
	err = decoder.Decode(&config)
	if err != nil {
		logError("Failed to parse config file: %v", err)
		return nil, err
	}

	return &config, nil
}

// Logger for structured logging
func logInfo(format string, args ...interface{}) {
	log.Printf("[INFO] "+format, args...)
}

func logError(format string, args ...interface{}) {
	log.Printf("[ERROR] "+format, args...)
}

// GetBearerToken retrieves or refreshes the token
func (tm *TokenManager) GetBearerToken() (string, error) {
	if time.Now().Before(tm.ExpiryTime) {
		logInfo("Using cached token, valid until: %s", tm.ExpiryTime)
		return tm.Token, nil
	}

	logInfo("Fetching a new token from: %s", tm.AuthURL)
	// Prepare form data (instead of JSON payload)
	formData := url.Values{}
	formData.Set("client_id", tm.ClientID)
	// formData.Set("grant_type", tm.GrantType)
	formData.Set("grant_type", "password")
	// formData.Set("scope", tm.Scope)
	formData.Set("scope", "openid")
	formData.Set("username", tm.Username)
	formData.Set("password", tm.Password)
	formData.Set("client_secret", tm.ClientSecret)

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}, // ⚠️ Not recommended for production!
	}
	// req, err := http.NewRequest("POST", tm.AuthURL, bytes.NewBuffer(payloadBytes))
	req, err := http.NewRequest("POST", tm.AuthURL, strings.NewReader(formData.Encode()))

	if err != nil {
		logError("Failed to create request: %v", err)
		return "", err
	}

	// Set headers for form-encoded data
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// req.Header.Set("Content-Type", "application/json")
	// Send request
	resp, err := client.Do(req)
	if err != nil {
		logError("Failed to send auth request: %v", err)
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logError("Failed to read auth response: %v", err)
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		logError("Authentication failed: %s", string(body))
		return "", fmt.Errorf("authentication failed: %s", string(body))
	}

	var authResp AuthResponse
	if err := json.Unmarshal(body, &authResp); err != nil {
		logError("Failed to parse auth response: %v", err)
		return "", err
	}

	tm.Token = authResp.AccessToken
	tm.ExpiryTime = time.Now().Add(time.Duration(authResp.ExpiresIn) * time.Second)

	logInfo("New token retrieved, valid until: %s", tm.ExpiryTime)
	return tm.Token, nil
}

// HandleIncomingMessage processes WebSocket messages and makes an HTTP GET request
func HandleIncomingMessage(message string, token string, config *Config) {

	logInfo("Processing message: %s", message)
	// Pretty-print the incoming raw JSON message
	var prettyJSON bytes.Buffer
	err := json.Indent(&prettyJSON, []byte(message), "", "  ")
	if err != nil {
		logError("Failed to format JSON message: %v", err)
		logInfo("Raw message: %s", message) // Fallback to raw message
	} else {
		logInfo("Processing message:\n%s", prettyJSON.String())
	}

	// Define a structure for the message format you expect
	var messageData struct {
		Type string `json:"type"`
		Msg  struct {
			Client string `json:"client"`
		} `json:"msg"`
	}

	// Unmarshal the JSON message to extract the client value
	err = json.Unmarshal([]byte(message), &messageData)
	if err != nil {
		logError("Failed to parse message: %v", err)
		return
	}

	// Extract the client value from the message
	clientValue := messageData.Msg.Client
	if clientValue == "" {
		logError("Client value not found in the message.")
		return
	}

	logInfo("Extracted client value: %s", clientValue)

	// URL encode the received data to safely pass it in a GET request
	encodedClientValue := url.QueryEscape(clientValue)
	// Encode the query to avoid issues.
	encodedQuery := url.QueryEscape(config.Query)

	// Define the API URL and query parameters
	// apiBaseURL := "https://100.108.1.31/core/query/v1/eql"
	apiBaseURL := config.ApiBaseURL

	queryParams := fmt.Sprintf(
		// "?stream=a.b.c.d&namespaces=eda&query=.namespace.node&eventclient=%s",
		"?stream=a.b.c.d&namespaces=eda&query=%s&eventclient=%s",
		// config.Query,
		encodedQuery,
		encodedClientValue, // Use the URL-encoded message
	)

	// Construct the full URL
	fullURL := apiBaseURL + queryParams
	logInfo("Sending GET request to: %s", fullURL)

	// Create an HTTP client with TLS configuration
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // ⚠️ Not recommended for production!
		},
	}

	// Create a new GET request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		logError("Failed to create API request: %v", err)
		return
	}

	// Add required headers
	req.Header.Set("Authorization", "Bearer "+token)

	// Send the request
	resp, err := client.Do(req)
	if err != nil {
		logError("Failed to send API request: %v", err)
		return
	}
	defer resp.Body.Close()

	// Read response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logError("Failed to read API response: %v", err)
		return
	}

	logInfo("API response: %s", string(body))
}

// ConnectWebSocket establishes a WebSocket connection with automatic reconnection
func ConnectWebSocket(serverURL string, tokenManager *TokenManager, config *Config) {
	reconnectDelay := 2 * time.Second
	maxDelay := 30 * time.Second

	for {
		bearerToken, err := tokenManager.GetBearerToken()
		if err != nil {
			logError("Failed to get token: %v", err)
			time.Sleep(reconnectDelay)
			continue
		}
		// Create a WebSocket dialer with TLS skip verification
		dialer := websocket.Dialer{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // ⚠️ Not safe for production!
		}
		headers := http.Header{}
		headers.Set("Authorization", "Bearer "+bearerToken)

		conn, _, err := dialer.Dial(serverURL, headers)
		// conn, _, err := websocket.DefaultDialer.Dial(serverURL, headers)
		if err != nil {
			if strings.Contains(err.Error(), "403") || strings.Contains(err.Error(), "401") {
				logInfo("Token expired, refreshing...")
				tokenManager.GetBearerToken() // Force refresh
				time.Sleep(reconnectDelay)
				continue
			}
			logError("WebSocket connection failed: %v", err)
			time.Sleep(reconnectDelay)
			reconnectDelay *= 2
			if reconnectDelay > maxDelay {
				reconnectDelay = maxDelay
			}
			continue
		}

		logInfo("Connected to WebSocket Server: %s", serverURL)
		reconnectDelay = 2 * time.Second // Reset delay after successful connection

		// Listen for messages
		go func() {
			// Flag to ensure HandleIncomingMessage is called only once
			var messageHandled bool

			for {
				_, message, err := conn.ReadMessage()
				if err != nil {
					logError("WebSocket read error: %v", err)
					break
				}
				// Pretty-print the received JSON message
				var prettyJSON bytes.Buffer
				err = json.Indent(&prettyJSON, message, "", "  ")
				if err != nil {
					logError("Failed to format JSON message: %v", err)
					logInfo("Raw message: %s", string(message)) // Fallback to raw message
				} else {
					logInfo("Message received successfully:\n%s", prettyJSON.String())
				}
				// logInfo("Received: %s", string(message))
				// Call HTTP API with received message		// If message hasn't been processed yet, call HandleIncomingMessage
				if !messageHandled {
					logInfo("First message received, handling it.")
					HandleIncomingMessage(string(message), bearerToken, config)
					messageHandled = true // Set flag to prevent further calls
				}
				// } else {
				// 	logInfo("Message received ")
				// }

				// HandleIncomingMessage(string(message), bearerToken)
			}
		}()

		// Send messages periodically
		msg := WebSocketMessage{
			Type:   "next",
			Stream: "a.b.c.d",
		}
		messageBytes, err := json.Marshal(msg)
		if err != nil {
			logError("Failed to marshal message to JSON: %v", err)
			break
		}

		for {
			err := conn.WriteMessage(websocket.TextMessage, messageBytes)
			if err != nil {
				logError("WebSocket write error: %v", err)
				break
			}
			// logInfo("Sent message successfully")
			// time.Sleep(5 * time.Second)
			time.Sleep(time.Duration(config.MessageInterval) * time.Second)
		}

		conn.Close()
		logInfo("Disconnected. Attempting to reconnect in %v...", reconnectDelay)
		time.Sleep(reconnectDelay)
	}
}

func main() {
	// Load the configuration from the config.json file
	config, err := LoadConfig("config.json")
	if err != nil {
		log.Fatal("Error loading config: ", err)
	}
	serverURL := config.ServerURL
	tokenManager := &TokenManager{
		Username:     config.Username,
		Password:     config.Password,
		AuthURL:      config.AuthURL,
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
	}

	go ConnectWebSocket(serverURL, tokenManager, config)

	// Keep the main function running
	select {}
}
