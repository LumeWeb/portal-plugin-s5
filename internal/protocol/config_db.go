package protocol

import (
	"errors"
	"github.com/samber/lo"
	"go.lumeweb.com/portal/config"
)

var _ config.ProtocolConfig = (*CacheConfig)(nil)
var _ config.Validator = (*DbConfig)(nil)

type DbConfig struct {
	Type   string      `mapstructure:"type"`
	DbPath string      `mapstructure:"db_path,omitempty"`
	Cache  CacheConfig `mapstructure:"cache"`
}

func (d DbConfig) Validate() error {
	if !lo.Contains([]string{"bolt", "etcd"}, d.Type) {
		return errors.New("db.type must be one of: bolt, etcd")
	}

	return nil
}

func (d DbConfig) Defaults() map[string]any {
	defaults := map[string]any{}

	if d.Type == "bolt" || d.Type == "" {
		defaults["db_path"] = "s5.db"
	}

	defaults["type"] = "bolt"
	return defaults
}
