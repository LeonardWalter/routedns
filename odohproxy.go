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

func NewDoHClientPool(capacity int) *DoHClientPool {
	return &DoHClientPool{
		clients:  make(map[string]*DoHClient),
		capacity: capacity,
	}
}

func (p *DoHClientPool) AddClient(endpoint string, path string, opt DoHClientOptions) (*http.Client, error) {
	if len(p.clients) >= p.capacity {
		p.removeOldest()
	}

	Log.Debug("Adding new client to pool", "target", endpoint)
	newClient, err := NewDoHClient(endpoint, "https://"+endpoint+path, opt)
	if err != nil {
		return nil, err
	}

	newClient.lastUsed = time.Now()
	p.clients[endpoint] = newClient
	return newClient.client, nil
}

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
