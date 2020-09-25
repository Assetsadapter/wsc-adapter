module github.com/Assetsadapter/wsc-adapter

go 1.12

require (
	github.com/FISCO-BCOS/go-sdk v0.10.0
	github.com/aristanetworks/goarista v0.0.0-20200812190859-4cb0e71f3c0e // indirect
	github.com/asdine/storm v2.1.2+incompatible
	github.com/astaxie/beego v1.11.1
	github.com/blocktree/go-owcdrivers v1.0.12
	github.com/blocktree/go-owcrypt v1.0.1
	github.com/blocktree/openwallet v1.5.5
	github.com/deckarep/golang-set v1.7.1 // indirect
	github.com/ethereum/go-ethereum v1.9.10
	github.com/fjl/memsize v0.0.0-20190710130421-bcb5799ab5e5 // indirect
	github.com/gin-gonic/gin v1.5.0
	github.com/google/uuid v1.1.1
	github.com/hashicorp/golang-lru v0.5.4 // indirect
	github.com/huin/goupnp v1.0.0 // indirect
	github.com/imroc/req v0.2.3
	github.com/jackpal/go-nat-pmp v1.0.2 // indirect
	github.com/karalabe/hid v1.0.0 // indirect
	github.com/mattn/go-colorable v0.1.7 // indirect
	github.com/rjeczalik/notify v0.9.2 // indirect
	github.com/rs/cors v1.7.0 // indirect
	github.com/shopspring/decimal v0.0.0-20180709203117-cd690d0c9e24
	github.com/tidwall/gjson v1.2.1
	golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9
	gopkg.in/olebedev/go-duktape.v3 v3.0.0-20200619000410-60c24ae608a6 // indirect
)

//replace github.com/blocktree/openwallet => ../../openwallet
