package oauth2client

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"reflect"
)

const (
	// The URN for getting verification token offline
	oobCallbackUrn = "urn:ietf:wg:oauth:2.0:oob"
	// The URN for token request grant type jwt-bearer
	jwtBearerUrn = "urn:ietf:params:oauth:grant-type:jwt-bearer"
)

// Default 3LO authorization handler. Prints the authorization URL on stdout
// and reads the verification code from stdin.
func defaultAuthorizeFlowHandler(authorizeUrl string) (string, error) {
	// Print the url on console, let user authorize and paste the token back.
	fmt.Printf("Go to the following link in your browser:\n\n   %s\n\n", authorizeUrl)
	fmt.Println("Enter verification code: ")
	var code string
	fmt.Scanln(&code)
	return code, nil
}

func toString(s interface{}) string {
	return fmt.Sprintf("%v", s)
}

// Run 3LO authorization flow.
func (c *ThreeLeggedClient) authorizeFlow() (string, error) {
	// Marshaw a url to be printed on console. In web based oauth flow, the
	// browser should redirect the user to this url
	params := url.Values{
		"access_type":                 []string{"offline"},
		"auth_provider_x509_cert_url": nil,
		"redirect_uri":                []string{oobCallbackUrn},
		"response_type":               []string{"code"},
		"client_id":                   nil,
		"scope":                       []string{c.scope},
		"project_id":                  nil,
	}

	for key := range params {
		if val, ok := c.secret[key]; ok {
			params.Set(key, toString(val))
		}
	}

	// Call the handler function to handle the authorize url and get back
	// the verification code.
	return c.authorizeHandler(toString(c.secret["auth_uri"]) + "?" + params.Encode())
}

func (c *ClientBase)retrieveAccessToken(url string, params url.Values) (*Token, error) {
	response, err := http.PostForm(url, params)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	var token *Token

	if err := json.Unmarshal(body, &token); err != nil {
		return nil, err
	}

	if token.ExpiresIn != nil {
		expiry := int64(time.Now().Unix()) + int64(*token.ExpiresIn)
		token.Expiry = time.Unix(expiry, 0)
		token.ExpiresIn = nil
	}

	var storedToken StoredToken
	storedToken.TokenValue = token
	storedToken.Secret = c.secret
	storedToken.Scope = c.scope

	if jsonStr, err := json.MarshalIndent(storedToken, "", "  "); err == nil {
		c.store.Put(jsonStr)
	}

	return token, nil
}

// Run 3LO verification. Sends a request to auth_uri with a verification code.
func (c *ThreeLeggedClient)verifyFlow(code string) (*Token, error) {
	// Construct a POST request to fetch OAuth token with the verificaton code.
	params := url.Values{
		"client_id":    []string{toString(c.secret["client_id"])},
		"code":         []string{code},
		"scope":        []string{c.scope},
		"grant_type":   []string{"authorization_code"},
		"redirect_uri": []string{oobCallbackUrn},
	}
	if clientSecret, ok := c.secret["client_secret"]; ok {
		params.Set("client_secret", toString(clientSecret))
	}

	// Send the POST request and return token.
	return c.retrieveAccessToken(toString(c.secret["token_uri"]), params)
}

// Helper struct used in sign JWT
type sha256Opts struct{}

func (r sha256Opts) HashFunc() crypto.Hash {
	return crypto.SHA256
}

// Base64 encode a block without any trailing double equal signs.
func base64Encode(b []byte) string {
	return strings.TrimSuffix(base64.URLEncoding.EncodeToString(b), "==")
}

// Signer interface to support both RSA and ECDSA signing.
type pkeyInterface interface {
	Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error)
}

// Convert a map to a base64 encoded JSON string.
func mapToJsonBase64(m map[string]string) (string, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return base64Encode(b), nil
}

// Creates a JWT token for 2LO token request.
func (c *TwoLeggedClient)createJWT(pkey pkeyInterface) (string, error) {
	// A valid JWT has an "iat" timestamp and an "exp" timestamp. Get the current
	// time to create these timestamps.
	now := int(time.Now().Unix())

	// Construct the JWT header, which contains the private key id in the service
	// account secret.
	header := map[string]string{
		"typ": "JWT",
		"alg": "RS256",
		"kid": toString(c.secret["private_key_id"]),
	}

	// Construct the JWT payload.
	payload := map[string]string{
		"aud":   toString(c.secret["token_uri"]),
		"scope": c.scope,
		"iat":   strconv.Itoa(now),
		"exp":   strconv.Itoa(now + 3600),
		"iss":   toString(c.secret["client_email"]),
	}

	// Convert header and payload to base64-encoded JSON.
	headerB64, err := mapToJsonBase64(header)
	if err != nil {
		return "", err
	}
	payloadB64, err := mapToJsonBase64(payload)
	if err != nil {
		return "", err
	}

	// The first two segments of the JWT are signed. The signature is the third
	// segment.
	segments := headerB64 + "." + payloadB64

	// sign the hash, instead of the actual segments.
	hashed := sha256.Sum256([]byte(segments))
	signedBytes, err := pkey.Sign(rand.Reader, hashed[:], crypto.SignerOpts(sha256Opts{}))
	if err != nil {
		return "", err
	}

	// Generate the final JWT as
	// base64(header) + "." + base64(payload) + "." + base64(signature)
	return segments + "." + base64Encode(signedBytes), nil
}

func (c *ClientBase) readTokenStore() (*Token, error) {
	bytes, err := c.store.Get()
	if (err != nil) {
		return nil, err
	}

	var storedToken StoredToken
	if err := json.Unmarshal(bytes, &storedToken); err != nil {
		return nil, err
	}

	if !reflect.DeepEqual(storedToken.Secret, c.secret) || storedToken.Scope != c.scope {
		return nil, fmt.Errorf("Cached token having different secret or scope.")
	}

	expiry := storedToken.TokenValue.Expiry
	if time.Now().Before(expiry) {
		return storedToken.TokenValue, nil
	} else {
		return nil, fmt.Errorf("Cached token expired.")
	}
}

// Client interface for OAuth 2.
type Client interface {
	// GetToken gets an OAuth 2 token for the specified OAuth scope. This method
	// must be safe for concurrent use by multiple goroutines.
	//
	// returns: A Token object including both refreash token and access
	//     token. The returned Token must **not** be modified.
	GetToken() (*Token, error)

	// SetStore sets TokenStore to the current Client.
	SetStore(store TokenStore)

	// SetAuthorizeHandler sets the authorize flow handler to Client.
	// AuthorizeHandler is a function that handles 3LO authorization flow. It
	// take in an auth URL, let the user authorize access on that URL, and return
	// an verification code. If it is nil, the client will use the
	// defaultAuthorizeFlowHandler.
	SetAuthorizeHandler(handler func(string) (string, error))
}

type ClientBase struct {
	secret map[string]interface{}
	scope string
	store TokenStore
	authorizeHandler func(string) (string, error)
}

func (c *ClientBase) SetStore(s TokenStore) {
	c.store = s
}

func (c *ClientBase) SetAuthorizeHandler(h func(string) (string, error)) {
	c.authorizeHandler = h
}

type TwoLeggedClient struct {
	ClientBase
}

type ThreeLeggedClient struct {
	ClientBase
}

// Run 3LO flow, including a authorize flow and a verify flow.
func (c *ThreeLeggedClient) GetToken() (*Token, error) {
	// Check token store.
	token, err := c.readTokenStore()
	if err == nil {
		return token, nil
	}

	// In the authorize flow, user will paste a verification code back to console.
	code, err := c.authorizeFlow()
	if err != nil {
		return nil, err
	}

	// The verify flow takes in the verification code from authorize flow, sends a
	// POST request containing the code to fetch oauth token.
	return c.verifyFlow(code)
}

// Run 2LO flow. Create a JWT token and use it to fetch an OAuth token.
func (c *TwoLeggedClient) GetToken() (*Token, error) {
	// Check token store.
	token, err := c.readTokenStore()
	if err == nil {
		return token, nil
	}

	// Read the private key in service account secret.
	pemBytes := []byte(toString(c.secret["private_key"]))
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("Failed to read private key pem block.")
	}

	// Ignore error, handle the error case below.
	pkcs8key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	// Create a pkeyInterface object containing the private key. The
	// pkeyInterface object has a sign function to sign a hash.
	pkey, ok := pkcs8key.(pkeyInterface)
	if !ok {
		return nil, fmt.Errorf("Failed to parse private key.")
	}

	// Get the JWT token
	jwt, err := c.createJWT(pkey)
	if err != nil {
		return nil, err
	}

	// Construct the POST request to fetch the OAuth token.
	params := url.Values{
		"assertion":  []string{jwt},
		"grant_type": []string{jwtBearerUrn},
	}

	// Send the POST request and return token.
	return c.retrieveAccessToken(toString(c.secret["token_uri"]), params)
}

// NewClient create a new OAuth2 Client.
//
// secretBytes: a JSON string that represents either an OAuth client ID or a
// service account.
// scope: A space separated scope codes per
//     [OAuth 2.0 spec](https://tools.ietf.org/html/rfc6749).

func NewClient(secretBytes []byte, scope string) (Client, error) {
	var secret map[string]interface{}
	if err := json.Unmarshal(secretBytes, &secret); err != nil {
		return nil, err
	}

	// TODO: support "web" client secret by using a local web server.
	// According to the content in the json, decide whether to run three-legged
	// flow (for client secret) or two-legged flow (for service account).
	if installed, ok := secret["installed"]; ok {
		// When the secret contains "installed" field, it is a client secret. We
		// will run a three-legged flow
		installedMap, ok := installed.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("Malformatted secret json, expected map for param \"installed\"")
		}
		return &ThreeLeggedClient{ClientBase{installedMap, scope, nil, defaultAuthorizeFlowHandler}}, nil
	} else if tokenType, ok := secret["type"]; ok && "service_account" == tokenType {
		// If the token type is "service_account", we will run the two-legged flow
		return &TwoLeggedClient{ClientBase{secret, scope, nil, nil}}, nil
	} else {
		return nil, fmt.Errorf("Unsupported token type.")
	}
}
