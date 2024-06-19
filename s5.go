package s5

import (
	"go.lumeweb.com/portal-plugin-s5/internal"
	"go.lumeweb.com/portal-plugin-s5/internal/api"
	"go.lumeweb.com/portal-plugin-s5/internal/db"
	"go.lumeweb.com/portal-plugin-s5/internal/protocol"
	"go.lumeweb.com/portal/core"
)

func init() {
	core.RegisterPlugin(core.PluginInfo{
		ID: internal.ProtocolName,
		API: func() (core.API, []core.ContextBuilderOption, error) {
			return api.NewS5API()
		},
		Protocol: func() (core.Protocol, []core.ContextBuilderOption, error) {
			return protocol.NewS5Protocol()
		},
		Models: []any{
			&db.S5Challenge{},
		},
	})
}
