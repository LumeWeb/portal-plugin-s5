package protocol

import (
	"errors"
	"github.com/samber/lo"
	"go.lumeweb.com/portal/config"
)

var _ config.ProtocolConfig = (*Config)(nil)
var _ config.ProtocolConfig = (*DbConfig)(nil)

type CacheConfig struct {
	Type         string `mapstructure:"type"`
	LRUCacheSize int    `mapstructure:"lru_cache_size"`
}

func (c CacheConfig) Defaults() map[string]any {
	defaults := map[string]any{}

	if c.Type == "lru" || c.Type == "" {
		defaults["lru_cache_size"] = 1000
	}

	defaults["type"] = "lru"

	return defaults
}

func (c CacheConfig) Validate() error {
	if !lo.Contains([]string{"lru", "none"}, c.Type) {
		return errors.New("cache.type must be one of: lru, none")
	}

	if c.Type == "lru" && c.LRUCacheSize <= 0 {
		return errors.New("cache.lru_cache_size must be greater than 0")
	}

	return nil
}
