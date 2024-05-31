package s5

import (
	"github.com/LumeWeb/portal-plugin-s5/internal/api"
	"github.com/LumeWeb/portal-plugin-s5/internal/db"
	"github.com/LumeWeb/portal-plugin-s5/internal/protocol"
	"github.com/LumeWeb/portal/core"
)

func init() {
	core.RegisterPlugin(factory)
}

func factory() core.PluginInfo {
	return core.PluginInfo{
		ID: "s5",
		GetAPI: func(ctx *core.Context) (core.API, error) {
			return api.NewS5API(*ctx), nil
		},
		GetProtocol: func(ctx *core.Context) (core.Protocol, error) {
			return protocol.NewS5Protocol(*ctx)
		},
		Models: []any{
			&db.S5Challenge{},
		},
	}
}
