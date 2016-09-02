package oauth2client

type TokenStore interface {
	// Get the stored blob. This function should have reader lock inside if you
	// plan to use Client concurrently in multiple goroutines.
	Get() ([]byte, error)

	// Put the blob to this store. This function should have writer lock inside.
	Put([]byte) error
}

type StoredToken struct {
	TokenValue *Token `json:"token"`

	Secret map[string]interface{} `json:"secret"`

	Scope string `json:"scope"`
}