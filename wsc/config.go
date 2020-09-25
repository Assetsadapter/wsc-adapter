/*
 * Copyright 2018 The openwallet Authors
 * This file is part of the openwallet library.
 *
 * The openwallet library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The openwallet library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 */
package wsc

import (
	"errors"
	"fmt"
	"math/big"
	"path/filepath"
	"strings"

	//	"github.com/astaxie/beego/config"

	"github.com/astaxie/beego/config"
	"github.com/blocktree/go-owcrypt"
	"github.com/blocktree/openwallet/common/file"
	"github.com/blocktree/openwallet/log"
)

const (
	//	BLOCK_CHAIN_DB     = "blockchain.db"
	BLOCK_CHAIN_BUCKET = "blockchain"
	ERC20TOKEN_DB      = "erc20Token.db"
)

const (
	Symbol          = "WSC"
	ContractAddress = "0xbaeec028b1f9eda0b6b015a437999634c3dd114b"
	MasterKey       = "Ethereum seed"
	TIME_POSTFIX    = "20060102150405"
	CurveType       = owcrypt.ECC_CURVE_SECP256K1

//	CHAIN_ID     = 922337203685 //12
)

const (
	ETH_GET_TOKEN_BALANCE_METHOD      = "0x70a08231"
	ETH_TRANSFER_TOKEN_BALANCE_METHOD = "0xa9059cbb"
	ETH_TRANSFER_EVENT_ID             = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
)

const (
	SOLIDITY_TYPE_ADDRESS = "address"
	SOLIDITY_TYPE_UINT256 = "uint256"
	SOLIDITY_TYPE_UINT160 = "uint160"
)

type WalletConfig struct {

	//币种
	Symbol    string
	MasterKey string
	RootDir   string
	//RPC认证账户名
	//RpcUser string
	//RPC认证账户密码
	//RpcPassword string
	//证书目录
	//CertsDir string
	//钥匙备份路径
	KeyDir string
	//地址导出路径
	AddressDir string
	//配置文件路径
	ConfigFilePath string
	//配置文件名
	ConfigFileName string
	//rpc证书
	//CertFileName string
	//区块链数据文件
	//BlockchainFile string
	//是否测试网络
	IsTestNet bool
	// 核心钱包是否只做监听
	//CoreWalletWatchOnly bool
	//最大的输入数量
	//MaxTxInputs int
	//本地数据库文件路径
	DbPath string
	//备份路径
	BackupDir string
	//钱包服务API
	ServerAPI string
	//钱包安装的路径
	//NodeInstallPath string
	//钱包数据文件目录
	//WalletDataPath string
	//汇总阀值
	//ThreaholdStr string
	Threshold *big.Int `json:"-"`
	//汇总地址
	SumAddress string
	//汇总执行间隔时间
	CycleSeconds uint64 //time.Duration
	//默认配置内容
	//	DefaultConfig string
	//曲线类型
	CurveType uint32
	//小数位长度
	//	CoinDecimal decimal.Decimal `json:"-"`
	EthereumKeyPath string
	//是否完全依靠本地维护nonce
	LocalNonce bool
	ChainID    uint64
	//数据目录
	DataDir string
	//固定gasLimit值
	FixGasLimit *big.Int
}

func makeEthDefaultConfig(ConfigFilePath string) string {

	defaultConfigStr := `
`
	return fmt.Sprintf(defaultConfigStr, CurveType)
}

func NewConfig(symbol string) *WalletConfig {
	c := WalletConfig{}
	c.Symbol = symbol
	c.CurveType = CurveType
	//区块链数据文件
	//c.BlockchainFile = "blockchain.db"
	//本地数据库文件路径
	c.DbPath = filepath.Join("data", strings.ToLower(c.Symbol), "db")

	//创建目录
	//file.MkdirAll(c.DbPath)

	return &c
}

//InitAssetsConfig 初始化默认配置
func (this *WalletManager) InitAssetsConfig() (config.Configer, error) {
	return config.NewConfigData("ini", []byte(this.DefaultConfig))
}

func (this *WalletManager) LoadAssetsConfig(c config.Configer) error {

	//this.Config.Symbol = c.String("Config.Symbol")     //SymbolID
	//this.Config.MasterKey = c.String("MasterKey") //MasterKey
	//curveType, err := c.Int64("CurveType")        //CurveType
	//if err != nil {
	//	log.Error("curve type failed, err=", err)
	//	return err
	//}

	//this.Config.CurveType = CurveType
	//this.Config.RootDir = c.String("RootDir") //rootDir
	////钥匙备份路径
	//this.Config.KeyDir = c.String("KeyDir") //filepath.Join(rootDir, "eth", "key")
	////地址导出路径
	//this.Config.AddressDir = c.String("AddressDir") //filepath.Join(rootDir, "eth", "address")
	//区块链数据
	//blockchainDir = filepath.Join(rootDir, strings.ToLower(SymbolID), "blockchain")
	//配置文件路径
	//this.Config.ConfigFilePath = c.String("ConfigFilePath") //ConfigFilePath //filepath.Join(rootDir, "eth", "conf") //filepath.Join("conf")
	////配置文件名
	//this.Config.ConfigFileName = c.String("ConfigFileName") //"eth.ini"
	//区块链数据文件
	//this.Config.BlockchainFile = c.String("BlockchainFile") //"blockchain.db"
	//是否测试网络
	//isTestNet, err := c.Bool("isTestNet")
	//if err != nil {
	//	log.Error("isTestNet error, err=", err)
	//	return err
	//}
	//this.Config.IsTestNet = isTestNet //true

	//本地数据库文件路径
	//this.Config.DbPath = c.String("DbPath") //filepath.Join(rootDir, "eth", "db")
	//备份路径
	//this.Config.BackupDir = c.String("BackupDir") //filepath.Join(rootDir, "eth", "backup")
	//钱包服务API
	this.Config.ServerAPI = c.String("ServerAPI") //"http://127.0.0.1:8545"

	//threshold, err := c.Int64("Threshold")
	//if err != nil {
	//	log.Error("Threshold error, err=", err)
	//	return err
	//}
	//this.Config.Threshold = big.NewInt(threshold) //decimal.NewFromFloat(5)
	//this.ThreaholdStr = "5"
	//汇总地址
	//this.Config.SumAddress = c.String("SumAddress") //""
	//汇总执行间隔时间
	//cycleSeconds, err := c.Int64("CycleSeconds")
	//if err != nil {
	//	log.Error("CycleSeconds error, err=", err)
	//	return err
	//}
	//this.Config.CycleSeconds = uint64(cycleSeconds) //c.Int64("CycleSeconds")
	//	this.ChainId = 12
	//this.Config.EthereumKeyPath = c.String("EthereumKeyPath") //"/Users/peter/workspace/bitcoin/wallet/src/github.com/wsc/go-wsc/chain/keystore"
	//每次都向节点查询nonce
	//localnonce, err := c.Bool("LocalNonce")
	//if err != nil {
	//	log.Error("LocalNonce error, err=", err)
	//	return err
	//}
	//this.Config.LocalNonce = localnonce //c.Bool("LocalNonce")
	//区块链ID
	chainId, err := c.Int64("ChainID")
	if err != nil {
		log.Error("ChainID error, err=", err)
		return err
	}
	this.Config.ChainID = uint64(chainId) //c.Int64("ChainID") //12

	//this.StorageOld = keystore.NewHDKeystore(this.Config.KeyDir, keystore.StandardScryptN, keystore.StandardScryptP)
	//storage := hdkeystore.NewHDKeystore(this.Config.KeyDir, hdkeystore.StandardScryptN, hdkeystore.StandardScryptP)
	//this.Storage = storage
	client := &Client{BaseURL: this.Config.ServerAPI, Debug: false}
	this.WalletClient = client
	this.Config.DataDir = c.String("dataDir")
	fixGasLimit := c.String("fixGasLimit")
	this.Config.FixGasLimit = new(big.Int)
	this.Config.FixGasLimit.SetString(fixGasLimit, 10)

	//数据文件夹
	this.Config.makeDataDir()

	return nil
}

func (this *WalletConfig) LoadConfig(configFilePath string, configFileName string) (*WalletConfig, error) {
	absFile := filepath.Join(configFilePath, configFileName)
	fmt.Println("config path:", absFile)
	c, err := config.NewConfig("ini", absFile)
	if err != nil {
		return nil, errors.New("Config is not setup. Please run 'wmd Config -s <symbol>' ")
	}

	this.Symbol = c.String("SymbolID")     //SymbolID
	this.MasterKey = c.String("MasterKey") //MasterKey
	curveType, err := c.Int64("CurveType") //CurveType
	if err != nil {
		log.Error("curve type failed, err=", err)
		return nil, err
	}

	this.CurveType = uint32(curveType) //CurveType
	this.RootDir = c.String("RootDir") //rootDir
	//钥匙备份路径
	this.KeyDir = c.String("KeyDir") //filepath.Join(rootDir, "eth", "key")
	//地址导出路径
	this.AddressDir = c.String("AddressDir") //filepath.Join(rootDir, "eth", "address")
	//区块链数据
	//blockchainDir = filepath.Join(rootDir, strings.ToLower(SymbolID), "blockchain")
	//配置文件路径
	this.ConfigFilePath = c.String("ConfigFilePath") //ConfigFilePath //filepath.Join(rootDir, "eth", "conf") //filepath.Join("conf")
	//配置文件名
	this.ConfigFileName = c.String("ConfigFileName") //"eth.ini"
	//区块链数据文件
	//this.BlockchainFile = c.String("BlockchainFile") //"blockchain.db"
	//是否测试网络
	isTestNet, err := c.Bool("isTestNet")
	if err != nil {
		log.Error("isTestNet error, err=", err)
		return nil, err
	}
	this.IsTestNet = isTestNet //true

	//本地数据库文件路径
	this.DbPath = c.String("DbPath") //filepath.Join(rootDir, "eth", "db")
	//备份路径
	this.BackupDir = c.String("BackupDir") //filepath.Join(rootDir, "eth", "backup")
	//钱包服务API
	this.ServerAPI = c.String("ServerAPI") //"http://127.0.0.1:8545"

	threshold, err := c.Int64("Threshold")
	if err != nil {
		log.Error("Threshold error, err=", err)
		return nil, err
	}
	this.Threshold = big.NewInt(threshold) //decimal.NewFromFloat(5)
	//this.ThreaholdStr = "5"
	//汇总地址
	this.SumAddress = c.String("SumAddress") //""
	//汇总执行间隔时间
	cycleSeconds, err := c.Int64("CycleSeconds")
	if err != nil {
		log.Error("CycleSeconds error, err=", err)
		return nil, err
	}
	this.CycleSeconds = uint64(cycleSeconds) //c.Int64("CycleSeconds")
	//	this.ChainId = 12
	this.EthereumKeyPath = c.String("EthereumKeyPath") //"/Users/peter/workspace/bitcoin/wallet/src/github.com/wsc/go-wsc/chain/keystore"
	//每次都向节点查询nonce
	localnonce, err := c.Bool("LocalNonce")
	if err != nil {
		log.Error("LocalNonce error, err=", err)
		return nil, err
	}
	this.LocalNonce = localnonce //c.Bool("LocalNonce")
	//区块链ID
	chainId, err := c.Int64("ChainID")
	if err != nil {
		log.Error("ChainID error, err=", err)
		return nil, err
	}
	this.ChainID = uint64(chainId) //c.Int64("ChainID") //12
	return this, nil
}

func (this *WalletManager) PrintConfig() error {
	this.InitConfig()
	//读取配置
	absFile := filepath.Join(this.ConfigPath, this.Config.Symbol+".ini")
	fmt.Printf("-----------------------------------------------------------\n")
	file.PrintFile(absFile)
	fmt.Printf("-----------------------------------------------------------\n")
	return nil

}

//initConfig 初始化配置文件
func (this *WalletManager) InitConfig() {

	//读取配置
	absFile := filepath.Join(this.ConfigPath, this.Config.Symbol+".ini")
	if !file.Exists(absFile) {
		file.MkdirAll(this.ConfigPath)
		file.WriteFile(absFile, []byte(this.DefaultConfig), false)
	}
}

//初始化配置流程
func (this *WalletManager) InitConfigFlow() error {

	this.InitConfig()
	file := filepath.Join(this.ConfigPath, this.Config.Symbol+".ini")
	fmt.Printf("You can run 'vim %s' to edit wallet's Config.\n", file)
	return nil
}

//查看配置信息
func (wm *WalletManager) ShowConfig() error {
	return wm.PrintConfig()
}

//创建文件夹
func (wc *WalletConfig) makeDataDir() {

	if len(wc.DataDir) == 0 {
		//默认路径当前文件夹./data
		wc.DataDir = "data"
	}

	//本地数据库文件路径
	wc.DbPath = filepath.Join(wc.DataDir, strings.ToLower(wc.Symbol), "db")

	//创建目录
	file.MkdirAll(wc.DbPath)
}
