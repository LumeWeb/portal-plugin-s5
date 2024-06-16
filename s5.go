package s5

import (
	"go.lumeweb.com/portal-plugin-s5/internal/api"
	"go.lumeweb.com/portal-plugin-s5/internal/db"
	"go.lumeweb.com/portal-plugin-s5/internal/protocol"
	"go.lumeweb.com/portal/core"
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
