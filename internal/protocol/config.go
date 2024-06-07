package protocol

import (
	"errors"
	s5config "github.com/LumeWeb/libs5-go/config"
	"github.com/LumeWeb/portal/config"
	"github.com/samber/lo"
)

var _ config.Validator = (*Config)(nil)
var _ config.Validator = (*CacheConfig)(nil)

type Config struct {
	*s5config.NodeConfig `mapstructure:",squash"`
	Db                   DbConfig `mapstructure:"db"`
	TUSLockerMode        string   `mapstructure:"tus_locker_mode"`
}

func (c Config) Validate() error {
	if c.TUSLockerMode != "" && !lo.Contains([]string{"db", "etcd"}, c.TUSLockerMode) {
		return errors.New("tus_locker_mode must be one of: db, etcd")
	}

	return nil
}

func (c Config) Defaults() map[string]any {
	defaults := map[string]any{}

	defaults["p2p.peers.initial"] = []string{
		"wss://z2DWuWNZcdSyZLpXFK2uCU3haaWMXrDAgxzv17sDEMHstZb@s5.garden/s5/p2p",
		"wss://z2DWuPbL5pweybXnEB618pMnV58ECj2VPDNfVGm3tFqBvjF@s5.ninja/s5/p2p",
	}

	defaults["p2p.max_connection_attempts"] = 10
	defaults["tus_locker_mode"] = "db"

	return defaults
}
