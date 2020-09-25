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
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"io/ioutil"
	"math/big"
	"path/filepath"
	"strconv"
	"time"

	"github.com/asdine/storm"
	"github.com/blocktree/go-owcrypt"
	"github.com/blocktree/openwallet/common/file"
	"github.com/blocktree/openwallet/hdkeystore"
	"github.com/blocktree/openwallet/log"
	"github.com/blocktree/openwallet/openwallet"
)

type Wallet struct {
	WalletID     string   `json:"rootid" storm:"id"`
	Alias        string   `json:"alias"`
	balance      *big.Int //string `json:"balance"`
	erc20Token   *ERC20Token
	Password     string `json:"password"`
	RootPub      string `json:"rootpub"`
	RootPath     string
	KeyFile      string
	HdPath       string
	PublicKey    string
	AddressCount uint64
}

type ERC20Token struct {
	Address  string `json:"address" storm:"id"`
	Symbol   string `json:"symbol" storm:"index"`
	Name     string `json:"name"`
	Decimals int    `json:"Decimals"`
	balance  *big.Int
}

type EthEvent struct {
	Address string   `json:"address"`
	Topics  []string `json:"topics"`
	Data    string   `josn:"data"`
	//BlockNumber string
	LogIndex string `json:"logIndex"`
	Removed  bool   `json:"removed"`
}

type EthTransactionReceipt struct {
	Logs    []EthEvent `json:"logs"`
	GasUsed string     `json:"gasUsed"`
	Status  string     `json:"status"`
}

type TransferEvent struct {
	ContractAddress string
	TokenFrom       string
	TokenTo         string
	Value           string
}

func (this *EthTransactionReceipt) ParseTransferEvent() map[string][]*TransferEvent {
	var (
		transferEvents = make(map[string][]*TransferEvent)
	)
	removePrefix0 := func(num string) string {
		num = removeOxFromHex(num)
		array := []byte(num)
		i := 0

		for i, _ = range num {
			if num[i] != '0' {
				break
			}
		}

		return string(array[i:len(num)])
	}

	for i, _ := range this.Logs {
		if len(this.Logs[i].Topics) != 3 {
			continue
		}

		if this.Logs[i].Topics[0] != ETH_TRANSFER_EVENT_ID {
			continue
		}

		if len(this.Logs[i].Data) != 66 {
			continue
		}

		prefix := string([]byte(this.Logs[i].Topics[1])[0:26:26])
		if prefix != "0x000000000000000000000000" {
			continue
		}

		prefix = string([]byte(this.Logs[i].Topics[2])[0:26:26])
		if prefix != "0x000000000000000000000000" {
			continue
		}

		address := this.Logs[i].Address
		events := transferEvents[address]
		if events == nil {
			events = make([]*TransferEvent, 0)
		}

		te := &TransferEvent{}
		te.ContractAddress = this.Logs[i].Address
		te.TokenFrom = "0x" + string([]byte(this.Logs[i].Topics[1])[26:66:66])
		te.TokenTo = "0x" + string([]byte(this.Logs[i].Topics[2])[26:66:66])
		te.Value = "0x" + removePrefix0(this.Logs[i].Data)
		events = append(events, te)
		transferEvents[address] = events

		//return &transferEvent
	}
	return transferEvents
}

type Address struct {
	Address      string `json:"address" storm:"id"`
	Account      string `json:"account" storm:"index"`
	HDPath       string `json:"hdpath"`
	Index        int
	PublicKey    string
	balance      *big.Int //string `json:"balance"`
	tokenBalance *big.Int
	TxCount      uint64
	CreatedAt    time.Time
}

func (this *Address) CalcPrivKey(masterKey *hdkeystore.HDKey) ([]byte, error) {
	childKey, _ := masterKey.DerivedKeyWithPath(this.HDPath, owcrypt.ECC_CURVE_SECP256K1)
	keyBytes, err := childKey.GetPrivateKeyBytes()
	if err != nil {
		log.Error("get private key bytes, err=", err)
		return nil, err
	}
	return keyBytes, nil
}

func (this *Address) CalcHexPrivKey(masterKey *hdkeystore.HDKey) (string, error) {
	prikey, err := this.CalcPrivKey(masterKey)
	if err != nil {
		return "", err
	}
	return hexutil.Encode(prikey), nil
}

type BlockTransaction struct {
	Hash             string `json:"hash" storm:"id"`
	BlockNumber      string `json:"blockNumber" storm:"index"`
	BlockHash        string `json:"blockHash" storm:"index"`
	From             string `json:"from"`
	To               string `json:"to"`
	Gas              string `json:"gas"`
	GasPrice         string `json:"gasPrice"`
	Value            string `json:"value"`
	Data             string `json:"input"`
	TransactionIndex string `json:"transactionIndex"`
	Timestamp        string `json:"timestamp"`
	BlockHeight      uint64 //transaction scanning 的时候对其进行赋值
	FilterFunc       openwallet.BlockScanAddressFunc
	Status           uint64
}

func (this *BlockTransaction) GetAmountEthString() (string, error) {
	amount, err := ConvertToBigInt(this.Value, 16)
	if err != nil {
		log.Errorf("convert amount to big.int failed, err= %v", err)
		return "0", err
	}
	amountVal, err := ConverWeiStringToEthDecimal(amount.String())
	if err != nil {
		log.Errorf("convert tx.Amount to eth decimal failed, err=%v", err)
		return "0", err
	}
	return amountVal.String(), nil
}

func (this *BlockTransaction) GetTxFeeEthString() (string, error) {
	gasPrice, err := ConvertToBigInt(this.GasPrice, 16)
	if err != nil {
		log.Errorf("convert tx.GasPrice failed, err= %v", err)
		return "", err
	}

	gas, err := ConvertToBigInt(this.Gas, 16)
	if err != nil {
		log.Errorf("convert tx.Gas failed, err=%v", err)
		return "", err
	}
	fee := big.NewInt(0)
	fee.Mul(gasPrice, gas)
	feeprice, err := ConverWeiStringToEthDecimal(fee.String())
	if err != nil {
		log.Errorf("convert fee failed, err=%v", err)
		return "", err
	}
	return feeprice.String(), nil
}

/*
  "result": {
    "dbHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "extraData": [],
    "gasLimit": "0x0",
    "gasUsed": "0x0",
    "hash": "0x99576e7567d258bd6426ddaf953ec0c953778b2f09a078423103c6555aa4362d",
    "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "number": 1,
    "parentHash": "0x4f6394763c33c1709e5a72b202ad4d7a3b8152de3dc698cef6f675ecdaf20a3b",
    "receiptsRoot": "0x69a04fa6073e4fc0947bac7ee6990e788d1e2c5ec0fe6c2436d0892e7f3c09d2",
    "sealer": "0x2",
    "sealerList": [
      "11e1be251ca08bb44f36fdeedfaeca40894ff80dfd80084607a75509edeaf2a9c6fee914f1e9efda571611cf4575a1577957edfd2baa9386bd63eb034868625f",
      "78a313b426c3de3267d72b53c044fa9fe70c2a27a00af7fea4a549a7d65210ed90512fc92b6194c14766366d434235c794289d66deff0796f15228e0e14a9191",
      "95b7ff064f91de76598f90bc059bec1834f0d9eeb0d05e1086d49af1f9c2f321062d011ee8b0df7644bd54c4f9ca3d8515a3129bbb9d0df8287c9fa69552887e",
      "b8acb51b9fe84f88d670646be36f31c52e67544ce56faf3dc8ea4cf1b0ebff0864c6b218fdcd9cf9891ebd414a995847911bd26a770f429300085f37e1131f36"
    ],
    "signatureList": [
      {
        "index": "0x2",
        "signature": "0xae098aabc63a53b8dcb57da9a87f13aebf231bfe1704da88f125cee6b4b30ee0609d0720a97bed1900b96bc3e7a63584158340b5b7f802945241f61731f9358900"
      },
      {
        "index": "0x0",
        "signature": "0x411cb93f816549eba82c3bf8c03fa637036dcdee65667b541d0da06a6eaea80d16e6ca52bf1b08f77b59a834bffbc124c492ea7a1601d0c4fb257d97dc97cea600"
      },
      {
        "index": "0x3",
        "signature": "0xb5b41e49c0b2bf758322ecb5c86dc3a3a0f9b98891b5bbf50c8613a241f05f595ce40d0bb212b6faa32e98546754835b057b9be0b29b9d0c8ae8b38f7487b8d001"
      }
    ],
    "stateRoot": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "timestamp": "0x173ad8703d6",
    "transactionsRoot": "0xb563f70188512a085b5607cac0c35480336a566de736c83410a062c9acc785ad"
  }
 */
type BlockHeader struct {
	BlockNumber     string `json:"number" storm:"id"`
	BlockHash       string `json:"hash"`
	GasLimit        string `json:"gasLimit"`
	GasUsed         string `json:"gasUsed"`
	//Miner           string `json:"miner"`
	//Difficulty      string `json:"difficulty"`
	//TotalDifficulty string `json:"totalDifficulty"`
	PreviousHash    string `json:"parentHash"`
	BlockHeight     uint64 //RecoverBlockHeader的时候进行初始化
}

func (this *Wallet) SaveAddress(dbpath string, addr *Address) error {
	db, err := this.OpenDB(dbpath)
	if err != nil {
		log.Errorf("open db failed, err = %v", err)
		return err
	}
	defer db.Close()

	return db.Save(addr)
}

func (this *Wallet) ClearAllTransactions(dbPath string) {
	db, err := this.OpenDB(dbPath)
	if err != nil {
		log.Errorf("open db failed, err = %v", err)
		return
	}
	defer db.Close()

	var txs []BlockTransaction
	err = db.All(&txs)
	if err != nil {
		log.Errorf("get transactions failed, err = %v", err)
		return
	}
	for i, _ := range txs {
		//fmt.Println("BlockHash:", txs[i].BlockHash, " BlockNumber:", txs[i].BlockNumber, "TransactionId:", txs[i].Hash)
		err := db.DeleteStruct(&txs[i])
		if err != nil {
			log.Errorf("delete tx in wallet failed, err=%v", err)
			break
		}
	}

}

func (this *Wallet) RestoreFromDb(dbPath string) error {
	db, err := this.OpenDB(dbPath)
	if err != nil {
		log.Errorf("open db failed, err = %v", err)
		return err
	}
	defer db.Close()

	var w Wallet
	err = db.One("WalletID", this.WalletID, &w)
	if err != nil {
		log.Error("find wallet id[", this.WalletID, "] failed, err=", err)
		return err
	}

	wstr, _ := json.MarshalIndent(w, "", " ")
	log.Debugf("wallet:%v", string(wstr))
	*this = w
	return nil
}

func (this *Wallet) DumpWalletDB(dbPath string) {
	db, err := this.OpenDB(dbPath)
	if err != nil {
		log.Errorf("open db failed, err = %v", err)
		return
	}
	defer db.Close()

	var addresses []Address
	err = db.All(&addresses)
	if err != nil {
		log.Errorf("get address failed, err=%v", err)
		return
	}

	for i, _ := range addresses {
		fmt.Println("Address:", addresses[i].Address, " account:", addresses[i].Account, "hdpath:", addresses[i].HDPath)
	}

	var txs []BlockTransaction
	err = db.All(&txs)
	if err != nil {
		log.Errorf("get transactions failed, err = %v", err)
		return
	}

	for i, _ := range txs {
		//fmt.Println("BlockHash:", txs[i].BlockHash, " BlockNumber:", txs[i].BlockNumber, "TransactionId:", txs[i].Hash),
		fmt.Printf("print tx[%v] in block [%v] = %v\n", txs[i].Hash, txs[i].BlockNumber, txs[i])
	}
}

func (this *Wallet) SaveTransactions(dbPath string, txs []BlockTransaction) error {
	db, err := this.OpenDB(dbPath)
	if err != nil {
		log.Errorf("open db failed, err = %v", err)
		return err
	}
	defer db.Close()

	dbTx, err := db.Begin(true)
	if err != nil {
		log.Errorf("start transaction for db failed, err=%v", err)
		return err
	}
	defer dbTx.Rollback()

	for i, _ := range txs {
		err = dbTx.Save(&txs[i])
		if err != nil {
			log.Errorf("save transaction failed, err=%v", err)
			return err
		}
	}
	dbTx.Commit()
	return nil
}

func (this *Wallet) DeleteTransactionByHeight(dbPath string, height uint64) error {
	db, err := this.OpenDB(dbPath)
	if err != nil {
		log.Errorf("open db for delete txs failed, err = %v", err)
		return err
	}
	defer db.Close()

	var txs []BlockTransaction

	err = db.Find("BlockNumber", "0x"+strconv.FormatUint(height, 16), &txs)
	if err != nil && err != storm.ErrNotFound {
		log.Errorf("get transactions from block[%v] failed, err=%v", "0x"+strconv.FormatUint(height, 16), err)
		return err
	} else if err == storm.ErrNotFound {
		log.Infof("no transactions found in block[%v] ", "0x"+strconv.FormatUint(height, 16))
		return nil
	}

	txdb, err := db.Begin(true)
	if err != nil {
		log.Errorf("start dbtx for delete tx failed, err=%v", err)
		return err
	}
	defer txdb.Rollback()

	for i, _ := range txs {
		err = txdb.DeleteStruct(&txs[i])
		if err != nil {
			log.Errorf("delete tx[%v] failed, err=%v", txs[i].Hash, err)
			return err
		}
	}
	txdb.Commit()
	return nil
}

//HDKey 获取钱包密钥，需要密码
func (this *Wallet) HDKey2(password string) (*hdkeystore.HDKey, error) {

	if len(password) == 0 {
		log.Error("password of wallet empty.")
		return nil, fmt.Errorf("password is empty")
	}

	if len(this.KeyFile) == 0 {
		log.Error("keyfile empty in wallet.")
		return nil, errors.New("Wallet key is not exist!")
	}

	keyjson, err := ioutil.ReadFile(this.KeyFile)
	if err != nil {
		return nil, err
	}
	key, err := hdkeystore.DecryptHDKey(keyjson, password)
	if err != nil {
		return nil, err
	}
	return key, err
}

//openDB 打开钱包数据库
func (w *Wallet) OpenDB(dbPath string) (*storm.DB, error) {
	file.MkdirAll(dbPath)
	file := w.DBFile(dbPath)
	//	fmt.Println("dbpath:", dbPath, ", file:", file)
	return storm.Open(file)
}

func (w *Wallet) OpenDbByPath(path string) (*storm.DB, error) {
	return storm.Open(path)
}

//DBFile 数据库文件
func (w *Wallet) DBFile(dbPath string) string {
	return filepath.Join(dbPath, w.FileName()+".db")
}

//FileName 该钱包定义的文件名规则
func (w *Wallet) FileName() string {
	return w.Alias + "-" + w.WalletID
}

func OpenDB(dbPath string, dbName string) (*storm.DB, error) {
	file.MkdirAll(dbPath)
	//	fmt.Println("OpenDB dbpath:", dbPath+"/"+dbName)
	return storm.Open(dbPath + "/" + dbName)
}
