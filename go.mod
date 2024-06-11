module github.com/LumeWeb/portal-plugin-s5

go 1.22.1

toolchain go1.22.2

require (
	github.com/LumeWeb/httputil v0.0.0-20240601144746-504fd57b96e6
	github.com/LumeWeb/libs5-go v0.0.0-20240606191331-125741e0f4a6
	github.com/LumeWeb/portal v0.1.0-develop.3.0.20240611012546-f3b9205ff82d
	github.com/aws/aws-sdk-go-v2 v1.27.2
	github.com/aws/aws-sdk-go-v2/service/s3 v1.55.1
	github.com/ddo/rq v0.0.0-20190828174524-b3daa55fcaba
	github.com/dnslink-std/go v0.6.0
	github.com/gabriel-vasile/mimetype v1.4.4
	github.com/gorilla/handlers v1.5.2
	github.com/gorilla/mux v1.8.1
	github.com/rs/cors v1.11.0
	github.com/samber/lo v1.39.0
	github.com/tus/tusd-etcd3-locker v0.0.0-20200405122323-74aeca810256
	github.com/tus/tusd/v2 v2.4.0
	github.com/vmihailenco/msgpack/v5 v5.4.1
	go.uber.org/zap v1.27.0
	go.uber.org/zap/exp v0.2.0
	golang.org/x/crypto v0.24.0
	gorm.io/gorm v1.25.10
	nhooyr.io/websocket v1.8.11
)

require (
	github.com/AfterShip/email-verifier v1.4.0 // indirect
	github.com/aead/chacha20 v0.0.0-20180709150244-8b13a72661da // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.6.2 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.9 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.9 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.3.9 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.11.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.3.11 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.11.11 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.17.9 // indirect
	github.com/aws/smithy-go v1.20.2 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/boombuler/barcode v1.0.1 // indirect
	github.com/casbin/casbin/v2 v2.95.0 // indirect
	github.com/casbin/govaluate v1.1.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/coreos/go-semver v0.3.1 // indirect
	github.com/coreos/go-systemd/v22 v22.5.0 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/emirpasic/gods v1.18.1 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/fsnotify/fsnotify v1.7.0 // indirect
	github.com/getkin/kin-openapi v0.118.0 // indirect
	github.com/go-co-op/gocron/v2 v2.5.0 // indirect
	github.com/go-openapi/jsonpointer v0.21.0 // indirect
	github.com/go-openapi/swag v0.23.0 // indirect
	github.com/go-viper/mapstructure/v2 v2.0.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang-jwt/jwt/v5 v5.2.1 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gotd/contrib v0.20.0 // indirect
	github.com/hashicorp/golang-lru v1.0.2 // indirect
	github.com/hbollon/go-edlib v1.6.0 // indirect
	github.com/invopop/yaml v0.3.1 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/jonboulle/clockwork v0.4.0 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/julienschmidt/httprouter v1.3.0 // indirect
	github.com/klauspost/cpuid/v2 v2.2.8 // indirect
	github.com/klauspost/reedsolomon v1.12.1 // indirect
	github.com/knadh/koanf v1.5.0 // indirect
	github.com/knadh/koanf/v2 v2.1.1 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/miekg/dns v1.1.59 // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/mohae/deepcopy v0.0.0-20170929034955-c48cc78d4826 // indirect
	github.com/mr-tron/base58 v1.2.0 // indirect
	github.com/multiformats/go-base32 v0.1.0 // indirect
	github.com/multiformats/go-base36 v0.2.0 // indirect
	github.com/multiformats/go-multibase v0.2.0 // indirect
	github.com/olebedev/emitter v0.0.0-20230411050614-349169dec2ba // indirect
	github.com/perimeterx/marshmallow v1.1.5 // indirect
	github.com/pquerna/otp v1.4.0 // indirect
	github.com/prometheus/client_golang v1.19.1 // indirect
	github.com/prometheus/client_model v0.6.1 // indirect
	github.com/prometheus/common v0.53.0 // indirect
	github.com/prometheus/procfs v0.15.1 // indirect
	github.com/redis/go-redis/v9 v9.5.3 // indirect
	github.com/robfig/cron/v3 v3.0.1 // indirect
	github.com/shopspring/decimal v1.4.0 // indirect
	github.com/vmihailenco/tagparser/v2 v2.0.0 // indirect
	gitlab.com/NebulousLabs/errors v0.0.0-20200929122200-06c536cf6975 // indirect
	gitlab.com/NebulousLabs/fastrand v0.0.0-20181126182046-603482d69e40 // indirect
	go.etcd.io/bbolt v1.3.10 // indirect
	go.etcd.io/etcd v3.3.27+incompatible // indirect
	go.etcd.io/etcd/api/v3 v3.5.14 // indirect
	go.etcd.io/etcd/client/pkg/v3 v3.5.14 // indirect
	go.etcd.io/etcd/client/v3 v3.5.14 // indirect
	go.sia.tech/core v0.2.6 // indirect
	go.sia.tech/coreutils v0.0.5 // indirect
	go.sia.tech/jape v0.11.2-0.20240228204811-29a0f056d231 // indirect
	go.sia.tech/mux v1.2.0 // indirect
	go.sia.tech/renterd v1.0.7 // indirect
	go.sia.tech/siad v1.5.10-0.20230228235644-3059c0b930ca // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/exp v0.0.0-20240604190554-fc45aab8b7f8 // indirect
	golang.org/x/mod v0.18.0 // indirect
	golang.org/x/net v0.26.0 // indirect
	golang.org/x/sync v0.7.0 // indirect
	golang.org/x/sys v0.21.0 // indirect
	golang.org/x/text v0.16.0 // indirect
	golang.org/x/tools v0.22.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20240610135401-a8a62080eff3 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240610135401-a8a62080eff3 // indirect
	google.golang.org/grpc v1.64.0 // indirect
	google.golang.org/protobuf v1.34.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	lukechampine.com/blake3 v1.3.0 // indirect
	lukechampine.com/frand v1.4.2 // indirect
)

replace (
	github.com/gorilla/mux v1.8.1 => github.com/cornejong/gormux v0.0.0-20240526072501-ce1c97b033ec
	github.com/tus/tusd-etcd3-locker v0.0.0-20200405122323-74aeca810256 => github.com/LumeWeb/tusd-etcd3-locker v0.0.0-20240510103936-0d66760cf053
	github.com/tus/tusd/v2 v2.4.0 => github.com/LumeWeb/tusd/v2 v2.2.3-0.20240531203802-3185ee9b16f8
)
