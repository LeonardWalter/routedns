package rdns

import (
	"errors"
	"net/http"
	"sync"
	"time"
)

type DoHClientPool struct {
	clients  map[string]*DoHClient
	mu       sync.Mutex
	capacity int
}

// NewDoHClientPool initializes a pool with a specific capacity.
func NewDoHClientPool(capacity int) *DoHClientPool {
	return &DoHClientPool{
		clients:  make(map[string]*DoHClient),
		capacity: capacity,
	}
}

// AddClient creates and adds a new client, replacing the least recently used if capacity is exceeded.
func (p *DoHClientPool) AddClient(endpoint string, path string, opt DoHClientOptions) (*http.Client, error) {
	Log.Printf("Adding new client to pool [%s]", endpoint)

	if len(p.clients) >= p.capacity {
		p.removeOldest()
		Log.Printf("removing oldest")
	}

	id := generateID(endpoint) // Replace with your ID generation logic
	newClient, err := NewDoHClient(id, "https://"+endpoint+path, opt)
	if err != nil {
		return nil, err
	}

	newClient.lastUsed = time.Now()
	p.clients[endpoint] = newClient
	return newClient.client, nil
}

// GetClient checks if a client exists, creates it if not, and updates its last used time.
func (p *DoHClientPool) GetClient(endpoint string) (*http.Client, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	client, exists := p.clients[endpoint]
	if exists {
		client.lastUsed = time.Now()
		return client.client, nil
	}

	return nil, errors.New("client not found for endpoint: " + endpoint)
}

// removeOldest removes the least recently used client from the pool.
func (p *DoHClientPool) removeOldest() {
	var oldestKey string
	var oldestTime time.Time

	for key, client := range p.clients {
		if oldestKey == "" || client.lastUsed.Before(oldestTime) {
			oldestKey = key
			oldestTime = client.lastUsed
		}
	}

	if oldestKey != "" {
		delete(p.clients, oldestKey)
	}
}

func generateID(endpoint string) string {
	return endpoint
}
