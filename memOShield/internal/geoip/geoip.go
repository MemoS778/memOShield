package geoip

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/MemoS778/memOShield/internal/config"
)

// Info holds geographic and network intelligence for an IP.
type Info struct {
	Country  string  `json:"country"`
	Lat      float64 `json:"lat"`
	Lon      float64 `json:"lon"`
	ISP      string  `json:"isp"`
	Org      string  `json:"org"`
	Hostname string  `json:"hostname"`
}

// Client performs GeoIP lookups.
type Client struct {
	urlTemplate string
	httpClient  *http.Client
}

// NewClient creates a GeoIP client.
func NewClient() *Client {
	return &Client{
		urlTemplate: config.GeoIPURL,
		httpClient: &http.Client{
			Timeout: 3 * time.Second,
		},
	}
}

// Lookup fetches GeoIP + ISP + hostname info for an IP.
func (c *Client) Lookup(ip string) Info {
	result := Info{
		Country:  "Unknown",
		ISP:      "Unknown",
		Org:      "Unknown",
		Hostname: ip,
	}

	// GeoIP API call
	url := fmt.Sprintf(c.urlTemplate, ip)
	resp, err := c.httpClient.Get(url)
	if err != nil {
		log.Printf("GeoIP lookup failed: %v", err)
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		var data map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&data); err == nil {
			if v, ok := data["country_name"].(string); ok && v != "" {
				result.Country = v
			} else if v, ok := data["country"].(string); ok && v != "" {
				result.Country = v
			}
			if v, ok := data["latitude"].(float64); ok {
				result.Lat = v
			} else if v, ok := data["lat"].(float64); ok {
				result.Lat = v
			}
			if v, ok := data["longitude"].(float64); ok {
				result.Lon = v
			} else if v, ok := data["lon"].(float64); ok {
				result.Lon = v
			}
			if v, ok := data["org"].(string); ok && v != "" {
				result.ISP = v
				result.Org = v
			}
			if v, ok := data["isp"].(string); ok && v != "" {
				result.ISP = v
			}
		}
	}

	// Reverse DNS
	names, err := net.LookupAddr(ip)
	if err == nil && len(names) > 0 {
		result.Hostname = names[0]
	}

	return result
}
