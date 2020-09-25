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
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/Assetsadapter/wsc-adapter/wsc_txsigner"
	"github.com/Assetsadapter/wsc-adapter/wsc_txsigner/types"
	"github.com/google/uuid"
	"github.com/shopspring/decimal"

	"github.com/tidwall/gjson"

	//"log"
	"math/big"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/blocktree/go-owcrypt"
	"github.com/blocktree/openwallet/openwallet"
	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
)

type EthTxExtPara struct {
	Data     string `json:"data"`
	GasLimit string `json:"gasLimit"`
}

func NewEthTxExtPara(j gjson.Result) *EthTxExtPara {
	obj := EthTxExtPara{}
	obj.GasLimit = j.Get("gasLimit").String()
	obj.Data = j.Get("data").String()
	return &obj
}

/*func (this *EthTxExtPara) GetGasLimit() (uint64, error) {
	gasLimit, err := strconv.ParseUint(removeOxFromHex(this.GasLimit), 16, 64)
	if err != nil {
		this.wm.Log.Std.Error("parse gas limit to uint64 failed, err=%v", err)
		return 0, err
	}
	return gasLimit, nil
}*/

const (
	ADRESS_STATIS_OVERDATED_TIME = 30
)

type AddressTxStatistic struct {
	Address          string
	TransactionCount *uint64
	LastModifiedTime *time.Time
	Valid            *int //如果valid指针指向的整形为0, 说明该地址已经被清理线程清理
	AddressLocker    *sync.Mutex
	//1. 地址级别, 不可并发广播交易, 造成nonce混乱
	//2. 地址级别, 不可广播, 读取nonce同时进行, 会造成nonce混乱
}

func (this *AddressTxStatistic) UpdateTime() {
	now := time.Now()
	this.LastModifiedTime = &now
}

type WscTransactionDecoder struct {
	openwallet.TransactionDecoderBase
	AddrTxStatisMap *sync.Map
	//	DecoderLocker *sync.Mutex    //保护一些全局不可并发的操作, 如对AddrTxStatisMap的初始化
	wm *WalletManager //钱包管理者
}

func (this *WscTransactionDecoder) GetTransactionCount2(address string) (*AddressTxStatistic, uint64, error) {
	now := time.Now()
	valid := 1
	t := AddressTxStatistic{
		LastModifiedTime: &now,
		AddressLocker:    new(sync.Mutex),
		Valid:            &valid,
		Address:          address,
		TransactionCount: new(uint64),
	}

	v, loaded := this.AddrTxStatisMap.LoadOrStore(address, t)
	//LoadOrStore返回后, AddressLocker加锁前, map中的nonce可能已经被清理了, 需要检查valid是否为1
	txStatis := v.(AddressTxStatistic)
	txStatis.AddressLocker.Lock()
	txStatis.AddressLocker.Unlock()
	if loaded {
		if *txStatis.Valid == 0 {
			return nil, 0, errors.New("the node is busy, try it again later. ")
		}
		txStatis.UpdateTime()
		return &txStatis, *txStatis.TransactionCount, nil
	}
	nonce, err := this.wm.GetNonceForAddress2(AppendOxToAddress(address))
	if err != nil {
		this.wm.Log.Std.Error("get nonce for address via rpc failed, err=%v", err)
		return nil, 0, err
	}
	*txStatis.TransactionCount = nonce
	return &txStatis, *txStatis.TransactionCount, nil
}

func (this *WscTransactionDecoder) GetTransactionCount(address string) (uint64, error) {
	if this.AddrTxStatisMap == nil {
		return 0, errors.New("map should be initialized before using.")
	}

	v, exist := this.AddrTxStatisMap.Load(address)
	if !exist {
		return 0, errors.New("no records found to the key passed through.")
	}

	txStatis := v.(AddressTxStatistic)
	return *txStatis.TransactionCount, nil
}

func (this *WscTransactionDecoder) SetTransactionCount(address string, transactionCount uint64) error {
	if this.AddrTxStatisMap == nil {
		return errors.New("map should be initialized before using.")
	}

	v, exist := this.AddrTxStatisMap.Load(address)
	if !exist {
		return errors.New("no records found to the key passed through.")
	}

	now := time.Now()
	valid := 1
	txStatis := AddressTxStatistic{
		TransactionCount: &transactionCount,
		LastModifiedTime: &now,
		AddressLocker:    new(sync.Mutex),
		Valid:            &valid,
		Address:          address,
	}

	if exist {
		txStatis.AddressLocker = v.(AddressTxStatistic).AddressLocker
	} else {
		txStatis.AddressLocker = &sync.Mutex{}
	}

	this.AddrTxStatisMap.Store(address, txStatis)
	return nil
}

func (this *WscTransactionDecoder) RemoveOutdatedAddrStatic() {
	addrStatisList := make([]AddressTxStatistic, 0)
	this.AddrTxStatisMap.Range(func(k, v interface{}) bool {
		addrStatis := v.(AddressTxStatistic)
		if addrStatis.LastModifiedTime.Before(time.Now().Add(-1 * (ADRESS_STATIS_OVERDATED_TIME * time.Minute))) {
			addrStatisList = append(addrStatisList, addrStatis)
		}
		return true
	})

	clear := func(statis *AddressTxStatistic) {
		statis.AddressLocker.Lock()
		defer statis.AddressLocker.Unlock()
		if statis.LastModifiedTime.Before(time.Now().Add(-1 * (ADRESS_STATIS_OVERDATED_TIME * time.Minute))) {
			*statis.Valid = 0
			this.AddrTxStatisMap.Delete(statis.Address)
		}
	}

	for i, _ := range addrStatisList {
		clear(&addrStatisList[i])
	}
}

func (this *WscTransactionDecoder) RunClearAddrStatic() {
	go func() {
		for {
			time.Sleep(5 * time.Minute)
			this.RemoveOutdatedAddrStatic()
		}
	}()
}

func (this *WscTransactionDecoder) GetRawTransactionFeeRate() (feeRate string, unit string, err error) {
	//price, err := this.wm.WalletClient.wscGetGasPrice()
	//if err != nil {
	//	this.wm.Log.Errorf("get gas price failed, err=%v", err)
	//	return "", "Gas", err
	//}
	//
	//pricedecimal, err := ConverWeiStringToEthDecimal(price.String())
	//if err != nil {
	//	this.wm.Log.Errorf("wrong gas price format.")
	//}
	//return pricedecimal.String(), "Gas", nil
	return "0", "Gas", nil
}

func VerifyRawTransaction(rawTx *openwallet.RawTransaction) error {
	if len(rawTx.To) != 1 {
		//this.wm.Log.Error("only one to address can be set.")
		return errors.New("only one to address can be set.")
	}

	return nil
}

//NewTransactionDecoder 交易单解析器
func NewTransactionDecoder(wm *WalletManager) *WscTransactionDecoder {
	decoder := WscTransactionDecoder{}
	//	decoder.DecoderLocker = new(sync.Mutex)
	decoder.wm = wm
	decoder.AddrTxStatisMap = new(sync.Map)
	decoder.RunClearAddrStatic()
	return &decoder
}

func (this *WscTransactionDecoder) CreateSimpleRawTransaction(wrapper openwallet.WalletDAI, rawTx *openwallet.RawTransaction, tmpNonce *uint64) error {

	var (
		accountID       = rawTx.Account.AccountID
		findAddrBalance *AddrBalance
		feeInfo         *txFeeInfo
	)

	//check交易交易单基本字段
	err := VerifyRawTransaction(rawTx)
	if err != nil {
		return err
	}

	//获取wallet
	addresses, err := wrapper.GetAddressList(0, -1,
		"AccountID", accountID)
	if err != nil {
		return openwallet.NewError(openwallet.ErrAddressNotFound, err.Error())
	}

	if len(addresses) == 0 {
		return openwallet.Errorf(openwallet.ErrAccountNotAddress, "[%s] have not addresses", accountID)
	}

	searchAddrs := make([]string, 0)
	for _, address := range addresses {
		searchAddrs = append(searchAddrs, address.Address)
	}

	addrBalanceArray, err := this.wm.Blockscanner.GetBalanceByAddress(searchAddrs...)
	if err != nil {
		return openwallet.NewError(openwallet.ErrCallFullNodeAPIFailed, err.Error())
	}

	var amountStr, to string
	for k, v := range rawTx.To {
		to = k
		amountStr = v
		break
	}

	amount, _ := ConvertEthStringToWei(amountStr)

	//地址余额从大到小排序
	sort.Slice(addrBalanceArray, func(i int, j int) bool {
		a_amount, _ := decimal.NewFromString(addrBalanceArray[i].Balance)
		b_amount, _ := decimal.NewFromString(addrBalanceArray[j].Balance)
		if a_amount.LessThan(b_amount) {
			return true
		} else {
			return false
		}
	})

	for _, addrBalance := range addrBalanceArray {

		//检查余额是否超过最低转账
		addrBalance_BI, _ := ConvertEthStringToWei(addrBalance.Balance)

		//计算手续费
		feeInfo, err = this.wm.GetTransactionFeeEstimated(addrBalance.Address, to, amount, "")
		if err != nil {
			this.wm.Log.Std.Error("GetTransactionFeeEstimated from[%v] -> to[%v] failed, err=%v", addrBalance.Address, to, err)
			continue
		}

		//if rawTx.FeeRate != "" {
		//	feeInfo.GasPrice, _ = ConvertEthStringToWei(rawTx.FeeRate)
		//	feeInfo.CalcFee()
		//}

		//总消耗数量 = 转账数量 + 手续费
		totalAmount := new(big.Int)
		totalAmount.Add(amount, feeInfo.Fee)

		if addrBalance_BI.Cmp(totalAmount) < 0 {
			continue
		}

		//只要找到一个合适使用的地址余额就停止遍历
		findAddrBalance = &AddrBalance{Address: addrBalance.Address, Balance: addrBalance_BI}
		break
	}

	if findAddrBalance == nil {
		return openwallet.Errorf(openwallet.ErrInsufficientBalanceOfAccount, "the balance: %s is not enough", amountStr)
	}

	//最后创建交易单
	createTxErr := this.createRawTransaction(
		wrapper,
		rawTx,
		findAddrBalance,
		feeInfo,
		"",
		tmpNonce)
	if createTxErr != nil {
		return createTxErr
	}

	return nil
}

func (this *WscTransactionDecoder) CreateErc20TokenRawTransaction(wrapper openwallet.WalletDAI, rawTx *openwallet.RawTransaction) error {

	var (
		accountID       = rawTx.Account.AccountID
		findAddrBalance *AddrBalance
		feeInfo         *txFeeInfo
		errBalance      string
		errTokenBalance string
		callData        string
	)

	tokenDecimals := int(rawTx.Coin.Contract.Decimals)
	contractAddress := rawTx.Coin.Contract.Address

	//check交易交易单基本字段
	err := VerifyRawTransaction(rawTx)
	if err != nil {
		this.wm.Log.Std.Error("Verify raw tx failed, err=%v", err)
		return err
	}

	//获取wallet
	addresses, err := wrapper.GetAddressList(0, -1,
		"AccountID", accountID)
	if err != nil {
		return openwallet.NewError(openwallet.ErrAddressNotFound, err.Error())
	}

	if len(addresses) == 0 {
		return openwallet.Errorf(openwallet.ErrAccountNotAddress, "[%s] have not addresses", accountID)
	}

	searchAddrs := make([]string, 0)
	for _, address := range addresses {
		searchAddrs = append(searchAddrs, address.Address)
	}

	addrBalanceArray, err := this.wm.ContractDecoder.GetTokenBalanceByAddress(rawTx.Coin.Contract, searchAddrs...)
	if err != nil {
		return openwallet.NewError(openwallet.ErrCallFullNodeAPIFailed, err.Error())
	}

	var amountStr, to string
	for k, v := range rawTx.To {
		to = k
		amountStr = v
		break
	}

	//地址余额从大到小排序
	sort.Slice(addrBalanceArray, func(i int, j int) bool {
		a_amount, _ := decimal.NewFromString(addrBalanceArray[i].Balance.Balance)
		b_amount, _ := decimal.NewFromString(addrBalanceArray[j].Balance.Balance)
		if a_amount.LessThan(b_amount) {
			return true
		} else {
			return false
		}
	})

	tokenBalanceNotEnough := false
	balanceNotEnough := false

	for _, addrBalance := range addrBalanceArray {
		callData = ""

		//检查余额是否超过最低转账
		addrBalance_BI, _ := ConvertFloatStringToBigInt(addrBalance.Balance.Balance, tokenDecimals)

		amount, _ := ConvertFloatStringToBigInt(amountStr, tokenDecimals)

		if addrBalance_BI.Cmp(amount) < 0 {
			errTokenBalance = fmt.Sprintf("the token balance of all addresses is not enough")
			tokenBalanceNotEnough = true
			continue
		}

		data, createErr := makeERC20TokenTransData(contractAddress, to, amount)
		if createErr != nil {
			continue
		}

		//this.wm.Log.Debug("sumAmount:", sumAmount)
		//计算手续费
		fee, createErr := this.wm.GetTransactionFeeEstimated(addrBalance.Balance.Address, contractAddress, nil, data)
		if createErr != nil {
			this.wm.Log.Std.Error("GetTransactionFeeEstimated from[%v] -> to[%v] failed, err=%v", addrBalance.Balance.Address, to, createErr)
			return createErr
		}

		if rawTx.FeeRate != "" {
			fee.GasPrice, _ = ConvertEthStringToWei(rawTx.FeeRate) //ConvertToBigInt(rawTx.FeeRate, 16)
			fee.CalcFee()
		}

		//coinBalance, err := this.wm.WalletClient.GetAddrBalance2(AppendOxToAddress(addrBalance.Balance.Address), "pending")
		//if err != nil {
		//	continue
		//}

		//if coinBalance.Cmp(fee.Fee) < 0 {
		//	coinBalance, _ := ConverWeiStringToEthDecimal(coinBalance.String())
		//	errBalance = fmt.Sprintf("the [%s] balance: %s is not enough to call smart contract", rawTx.Coin.Symbol, coinBalance)
		//	balanceNotEnough = true
		//	continue
		//}

		//只要找到一个合适使用的地址余额就停止遍历
		findAddrBalance = &AddrBalance{Address: addrBalance.Balance.Address, Balance: big.NewInt(0), TokenBalance: addrBalance_BI}
		feeInfo = fee
		callData = data
		break
	}

	if findAddrBalance == nil {
		if tokenBalanceNotEnough {
			return openwallet.Errorf(openwallet.ErrInsufficientTokenBalanceOfAddress, errTokenBalance)
		}
		if balanceNotEnough {
			return openwallet.Errorf(openwallet.ErrInsufficientFees, errBalance)
		}
	}

	//最后创建交易单
	createTxErr := this.createRawTransaction(
		wrapper,
		rawTx,
		findAddrBalance,
		feeInfo,
		callData,
		nil)
	if createTxErr != nil {
		return createTxErr
	}

	return nil
}

//CreateRawTransaction 创建交易单
func (this *WscTransactionDecoder) CreateRawTransaction(wrapper openwallet.WalletDAI, rawTx *openwallet.RawTransaction) error {
	rawTx.Coin.IsContract = true
	contractId := base64.StdEncoding.EncodeToString(sha256.New().Sum([]byte("WSCToken" + "0xbaeec028b1f9eda0b6b015a437999634c3dd114b")))
	rawTx.Coin.ContractID = contractId
	rawTx.Coin.Contract = openwallet.SmartContract{
		ContractID: contractId,
		Symbol:     "WSC",
		Address:    "0xbaeec028b1f9eda0b6b015a437999634c3dd114b",
		Token:      "WSCToken",
		Protocol:   "erc20",
		Name:       "WSCToken",
		Decimals:   8,
	}
	if !rawTx.Coin.IsContract {
		return this.CreateSimpleRawTransaction(wrapper, rawTx, nil)
	}
	return this.CreateErc20TokenRawTransaction(wrapper, rawTx)
}

//SignRawTransaction 签名交易单
func (this *WscTransactionDecoder) SignRawTransaction(wrapper openwallet.WalletDAI, rawTx *openwallet.RawTransaction) error {

	//check交易交易单基本字段
	err := VerifyRawTransaction(rawTx)
	if err != nil {
		this.wm.Log.Std.Error("Verify raw tx failed, err=%v", err)
		return err
	}

	if rawTx.Signatures == nil || len(rawTx.Signatures) == 0 {
		//this.wm.Log.Std.Error("len of signatures error. ")
		return openwallet.Errorf(openwallet.ErrSignRawTransactionFailed, "transaction signature is empty")
	}

	key, err := wrapper.HDKey()
	if err != nil {
		this.wm.Log.Error("get HDKey from wallet wrapper failed, err=%v", err)
		return err
	}

	if _, exist := rawTx.Signatures[rawTx.Account.AccountID]; !exist {
		this.wm.Log.Std.Error("wallet[%v] signature not found ", rawTx.Account.AccountID)
		return openwallet.Errorf(openwallet.ErrSignRawTransactionFailed, "wallet signature not found ")
	}

	if len(rawTx.Signatures[rawTx.Account.AccountID]) != 1 {
		this.wm.Log.Error("signature failed in account[%v].", rawTx.Account.AccountID)
		return openwallet.Errorf(openwallet.ErrSignRawTransactionFailed, "signature failed in account.")
	}

	signnode := rawTx.Signatures[rawTx.Account.AccountID][0]
	fromAddr := signnode.Address

	childKey, _ := key.DerivedKeyWithPath(fromAddr.HDPath, owcrypt.ECC_CURVE_SECP256K1)
	keyBytes, err := childKey.GetPrivateKeyBytes()
	if err != nil {
		this.wm.Log.Error("get private key bytes, err=", err)
		return openwallet.NewError(openwallet.ErrSignRawTransactionFailed, err.Error())
	}

	message, err := hex.DecodeString(signnode.Message)
	if err != nil {
		return err
	}

	sig, err := wsc_txsigner.Default.SignTransactionHash(message, keyBytes, owcrypt.ECC_CURVE_SECP256K1)
	if err != nil {
		return err
	}

	height, err := this.wm.WalletClient.WscGetBlockNumber()
	if err != nil {
		return err
	}

	from := strings.Split(rawTx.TxFrom[0], ":")[0]
	to := strings.Split(rawTx.TxTo[0], ":")[0]

	amount := rawTx.TxAmount

	if strings.HasPrefix(amount, "-") {
		amount = amount[1:]
	}

	bigAmount, _ := ConvertFloatStringToBigInt(amount, 8)
	amount = bigAmount.String()

	tx, err := this.wm.WalletClient.SerializationTransaction(from, to, amount, fmt.Sprintf("%d", height), hex.EncodeToString(keyBytes))
	if err != nil {
		return err
	}

	signnode.Signature = hex.EncodeToString(sig)
	rawTx.RawHex = tx

	//this.wm.Log.Debug("** pri:", hex.EncodeToString(keyBytes))
	this.wm.Log.Debug("** message:", signnode.Message)
	this.wm.Log.Debug("** Signature:", signnode.Signature)

	return nil
}

func (this *WscTransactionDecoder) SubmitSimpleRawTransaction(wrapper openwallet.WalletDAI, rawTx *openwallet.RawTransaction) (*openwallet.Transaction, error) {
	//check交易交易单基本字段
	err := VerifyRawTransaction(rawTx)
	if err != nil {
		this.wm.Log.Std.Error("Verify raw tx failed, err=%v", err)
		return nil, err
	}
	if len(rawTx.Signatures) != 1 {
		this.wm.Log.Std.Error("len of signatures error. ")
		return nil, openwallet.Errorf(openwallet.ErrSubmitRawTransactionFailed, "len of signatures error. ")
	}

	if _, exist := rawTx.Signatures[rawTx.Account.AccountID]; !exist {
		this.wm.Log.Std.Error("wallet[%v] signature not found ", rawTx.Account.AccountID)
		return nil, openwallet.Errorf(openwallet.ErrSubmitRawTransactionFailed, "wallet signature not found ")
	}

	from := rawTx.Signatures[rawTx.Account.AccountID][0].Address.Address
	//sig := rawTx.Signatures[rawTx.Account.AccountID][0].Signature

	this.wm.Log.Debug("rawTx.ExtParam:", rawTx.ExtParam)

	//signer := types.NewEIP155Signer(big.NewInt(int64(this.wm.GetConfig().ChainID)))

	txStatis, _, err := this.GetTransactionCount2(from)
	if err != nil {
		this.wm.Log.Std.Error("get transaction count2 failed, err=%v", err)
		return nil, openwallet.Errorf(openwallet.ErrSubmitRawTransactionFailed, "get transaction count2 faile")
	}

	//rawHex, err := hex.DecodeString(rawTx.RawHex)
	//if err != nil {
	//	this.wm.Log.Error("rawTx.RawHex decode failed, err:", err)
	//	return nil, err
	//}

	err = func() error {

		//tx := &types.Transaction{}
		//err = rlp.DecodeBytes(rawHex, tx)
		//if err != nil {
		//	this.wm.Log.Error("transaction RLP decode failed, err:", err)
		//	return err
		//}
		//
		//signer := types.HomesteadSigner{}
		//
		//tx, err = tx.WithSignature(signer, ethcommon.FromHex(sig))
		//if err != nil {
		//	this.wm.Log.Std.Error("tx with signature failed, err=%v ", err)
		//	return errors.New("tx with signature failed. ")
		//}
		//
		//txstr, _ := json.MarshalIndent(tx, "", " ")
		//this.wm.Log.Debug("**after signed txStr:", string(txstr))
		//
		//rawTxPara, err := rlp.EncodeToBytes(tx)
		//if err != nil {
		//	this.wm.Log.Std.Error("encode tx to rlp failed, err=%v ", err)
		//	return errors.New("encode tx to rlp failed. ")
		//}

		txid, err := this.wm.WalletClient.wscSendRawTransaction(rawTx.RawHex)
		if err != nil {
			this.wm.Log.Std.Error("sent raw tx faild, err=%v", err)
			return openwallet.Errorf(openwallet.ErrSubmitRawTransactionFailed, "sent raw tx faild. unexpected error: %v", err)
		}

		rawTx.TxID = txid
		rawTx.IsSubmit = true
		txStatis.UpdateTime()
		(*txStatis.TransactionCount)++

		this.wm.Log.Debug("transaction[", txid, "] has been sent out.")
		return nil
	}()

	if err != nil {
		this.wm.Log.Errorf("send raw transaction failed, err= %v", err)
		return nil, err
	}

	decimals := int32(0)
	if rawTx.Coin.IsContract {
		decimals = int32(rawTx.Coin.Contract.Decimals)
	} else {
		decimals = int32(this.wm.Decimal())
	}

	//记录一个交易单
	tx := &openwallet.Transaction{
		From:       rawTx.TxFrom,
		To:         rawTx.TxTo,
		Amount:     rawTx.TxAmount,
		Coin:       rawTx.Coin,
		TxID:       rawTx.TxID,
		Decimal:    decimals,
		AccountID:  rawTx.Account.AccountID,
		Fees:       rawTx.Fees,
		SubmitTime: time.Now().Unix(),
		TxType:     0,
	}

	tx.WxID = openwallet.GenTransactionWxID(tx)

	return tx, nil
}

func (this *WscTransactionDecoder) SubmitErc20TokenRawTransaction(wrapper openwallet.WalletDAI, rawTx *openwallet.RawTransaction) (*openwallet.Transaction, error) {
	//check交易交易单基本字段
	err := VerifyRawTransaction(rawTx)
	if err != nil {
		this.wm.Log.Std.Error("Verify raw tx failed, err=%v", err)
		return nil, err
	}
	if len(rawTx.Signatures) != 1 {
		this.wm.Log.Std.Error("len of signatures error. ")
		return nil, errors.New("len of signatures error. ")
	}

	if _, exist := rawTx.Signatures[rawTx.Account.AccountID]; !exist {
		this.wm.Log.Std.Error("wallet[%v] signature not found ", rawTx.Account.AccountID)
		return nil, errors.New("wallet signature not found ")
	}

	from := rawTx.Signatures[rawTx.Account.AccountID][0].Address.Address
	//sig := rawTx.Signatures[rawTx.Account.AccountID][0].Signature

	//extPara := NewEthTxExtPara(gjson.Parse(rawTx.ExtParam))
	//var extPara EthTxExtPara
	//this.wm.Log.Debug("rawTx.ExtParam:", rawTx.ExtParam)
	//err = json.Unmarshal([]byte(rawTx.ExtParam), &extPara)
	//if err != nil {
	//	this.wm.Log.Std.Error("decode json from extpara failed, err=%v", err)
	//	return err
	//}

	//data := extPara.Data
	//this.wm.Log.Debug("extPara.GasLimit:", extPara.GasLimit)
	//gaslimit, err := ConvertEthStringToWei(extPara.GasLimit) //extPara.GetGasLimit()
	//if err != nil {
	//	this.wm.Log.Std.Error("get gas limit failed, err=%v", err)
	//	return errors.New("get gas limit failed")
	//}

	//signer := types.NewEIP155Signer(big.NewInt(int64(this.wm.GetConfig().ChainID)))

	txStatis, _, err := this.GetTransactionCount2(from)
	if err != nil {
		this.wm.Log.Std.Error("get transaction count2 failed, err=%v", err)
		return nil, errors.New("get transaction count2 faile")
	}

	//rawHex, err := hex.DecodeString(rawTx.RawHex)
	//if err != nil {
	//	this.wm.Log.Error("rawTx.RawHex decode failed, err:", err)
	//	return nil, err
	//}

	err = func() error {
		//txStatis.AddressLocker.Lock()
		//defer txStatis.AddressLocker.Unlock()
		//
		//tx := &types.Transaction{}
		//err = rlp.DecodeBytes(rawHex, tx)
		//if err != nil {
		//	this.wm.Log.Error("transaction RLP decode failed, err:", err)
		//	return err
		//}
		//tx, err = tx.WithSignature(signer, ethcommon.FromHex(sig))
		//if err != nil {
		//	this.wm.Log.Std.Error("tx with signature failed, err=%v ", err)
		//	return errors.New("tx with signature failed. ")
		//}
		//
		//txstr, _ := json.MarshalIndent(tx, "", " ")
		//this.wm.Log.Debug("**after signed txStr:", string(txstr))
		//
		//rawTxPara, err := rlp.EncodeToBytes(tx)
		//if err != nil {
		//	this.wm.Log.Std.Error("encode tx to rlp failed, err=%v ", err)
		//	return errors.New("encode tx to rlp failed. ")
		//}

		txid, err := this.wm.WalletClient.wscSendRawTransaction(rawTx.RawHex)
		if err != nil {
			this.wm.Log.Std.Error("sent raw tx faild, err=%v", err)
			return openwallet.Errorf(openwallet.ErrSubmitRawTransactionFailed, "sent raw tx faild. unexpected error: %v", err)
		}

		rawTx.TxID = txid
		rawTx.IsSubmit = true
		txStatis.UpdateTime()
		(*txStatis.TransactionCount)++

		this.wm.Log.Debug("transaction[", txid, "] has been sent out.")
		return nil
	}()

	if err != nil {
		this.wm.Log.Errorf("send raw transaction failed, err= %v", err)
		return nil, err
	}

	decimals := int32(0)
	if rawTx.Coin.IsContract {
		decimals = int32(rawTx.Coin.Contract.Decimals)
	} else {
		decimals = int32(this.wm.Decimal())
	}

	//记录一个交易单
	tx := &openwallet.Transaction{
		From:       rawTx.TxFrom,
		To:         rawTx.TxTo,
		Amount:     rawTx.TxAmount,
		Coin:       rawTx.Coin,
		TxID:       rawTx.TxID,
		Decimal:    decimals,
		AccountID:  rawTx.Account.AccountID,
		Fees:       "0",
		SubmitTime: time.Now().Unix(),
		TxType:     0,
	}

	tx.WxID = openwallet.GenTransactionWxID(tx)

	return tx, nil
}

//SendRawTransaction 广播交易单
func (this *WscTransactionDecoder) SubmitRawTransaction(wrapper openwallet.WalletDAI, rawTx *openwallet.RawTransaction) (*openwallet.Transaction, error) {
	rawTx.Coin.IsContract = true
	contractId := base64.StdEncoding.EncodeToString(sha256.New().Sum([]byte("WSCToken" + "0xbaeec028b1f9eda0b6b015a437999634c3dd114b")))
	rawTx.Coin.ContractID = contractId
	rawTx.Coin.Contract = openwallet.SmartContract{
		ContractID: contractId,
		Symbol:     "WSC",
		Address:    "0xbaeec028b1f9eda0b6b015a437999634c3dd114b",
		Token:      "WSCToken",
		Protocol:   "erc20",
		Name:       "WSCToken",
		Decimals:   8,
	}
	if !rawTx.Coin.IsContract {
		return this.SubmitSimpleRawTransaction(wrapper, rawTx)
	}
	return this.SubmitErc20TokenRawTransaction(wrapper, rawTx)
}

//VerifyRawTransaction 验证交易单，验证交易单并返回加入签名后的交易单
func (this *WscTransactionDecoder) VerifyRawTransaction(wrapper openwallet.WalletDAI, rawTx *openwallet.RawTransaction) error {
	//check交易交易单基本字段
	err := VerifyRawTransaction(rawTx)
	if err != nil {
		this.wm.Log.Std.Error("Verify raw tx failed, err=%v", err)
		return err
	}

	if rawTx.Signatures == nil || len(rawTx.Signatures) == 0 {
		//this.wm.Log.Std.Error("len of signatures error. ")
		return openwallet.Errorf(openwallet.ErrVerifyRawTransactionFailed, "transaction signature is empty")
	}

	accountSig, exist := rawTx.Signatures[rawTx.Account.AccountID]
	if !exist {
		this.wm.Log.Std.Error("wallet[%v] signature not found ", rawTx.Account.AccountID)
		return errors.New("wallet signature not found ")
	}

	if len(accountSig) == 0 {
		//this.wm.Log.Std.Error("len of signatures error. ")
		return openwallet.Errorf(openwallet.ErrVerifyRawTransactionFailed, "transaction signature is empty")
	}

	sig := accountSig[0].Signature
	msg := accountSig[0].Message
	pubkey := accountSig[0].Address.PublicKey
	//curveType := rawTx.Signatures[rawTx.Account.AccountID][0].EccType

	this.wm.Log.Debug("-- pubkey:", pubkey)
	this.wm.Log.Debug("-- message:", msg)
	this.wm.Log.Debug("-- Signature:", sig)
	signature := ethcommon.FromHex(sig)
	publickKey := owcrypt.PointDecompress(ethcommon.FromHex(pubkey), owcrypt.ECC_CURVE_SECP256K1)
	publickKey = publickKey[1:len(publickKey)]
	ret := owcrypt.Verify(publickKey, nil, 0, ethcommon.FromHex(msg), 32, signature[0:len(signature)-1],
		owcrypt.ECC_CURVE_SECP256K1|owcrypt.HASH_OUTSIDE_FLAG)
	if ret != owcrypt.SUCCESS {
		errinfo := fmt.Sprintf("verify error, ret:%v\n", "0x"+strconv.FormatUint(uint64(ret), 16))
		fmt.Println(errinfo)
		return errors.New(errinfo)
	}

	return nil
}

//CreateSummaryRawTransaction 创建汇总交易，返回原始交易单数组
func (this *WscTransactionDecoder) CreateSummaryRawTransaction(wrapper openwallet.WalletDAI, sumRawTx *openwallet.SummaryRawTransaction) ([]*openwallet.RawTransaction, error) {
	var (
		rawTxWithErrArray []*openwallet.RawTransactionWithError
		rawTxArray        = make([]*openwallet.RawTransaction, 0)
		err               error
	)
	sumRawTx.Coin.IsContract = true
	contractId := base64.StdEncoding.EncodeToString(sha256.New().Sum([]byte("WSCToken" + "0xbaeec028b1f9eda0b6b015a437999634c3dd114b")))
	sumRawTx.Coin.ContractID = contractId
	sumRawTx.Coin.Contract = openwallet.SmartContract{
		ContractID: contractId,
		Symbol:     "WSC",
		Address:    "0xbaeec028b1f9eda0b6b015a437999634c3dd114b",
		Token:      "WSCToken",
		Protocol:   "erc20",
		Name:       "WSCToken",
		Decimals:   8,
	}
	if sumRawTx.Coin.IsContract {
		rawTxWithErrArray, err = this.CreateErc20TokenSummaryRawTransaction(wrapper, sumRawTx)
	} else {
		rawTxWithErrArray, err = this.CreateSimpleSummaryRawTransaction(wrapper, sumRawTx)
	}
	if err != nil {
		return nil, err
	}
	for _, rawTxWithErr := range rawTxWithErrArray {
		if rawTxWithErr.Error != nil {
			continue
		}
		rawTxArray = append(rawTxArray, rawTxWithErr.RawTx)
	}
	return rawTxArray, nil
}

//CreateSimpleSummaryRawTransaction 创建ETH汇总交易
func (this *WscTransactionDecoder) CreateSimpleSummaryRawTransaction(wrapper openwallet.WalletDAI, sumRawTx *openwallet.SummaryRawTransaction) ([]*openwallet.RawTransactionWithError, error) {

	var (
		rawTxArray         = make([]*openwallet.RawTransactionWithError, 0)
		accountID          = sumRawTx.Account.AccountID
		minTransfer, _     = ConvertEthStringToWei(sumRawTx.MinTransfer)
		retainedBalance, _ = ConvertEthStringToWei(sumRawTx.RetainedBalance)
	)

	if minTransfer.Cmp(retainedBalance) < 0 {
		return nil, openwallet.Errorf(openwallet.ErrCreateRawTransactionFailed, "mini transfer amount must be greater than address retained balance")
	}

	//获取wallet
	addresses, err := wrapper.GetAddressList(sumRawTx.AddressStartIndex, sumRawTx.AddressLimit,
		"AccountID", sumRawTx.Account.AccountID)
	if err != nil {
		return nil, err
	}

	if len(addresses) == 0 {
		return nil, openwallet.Errorf(openwallet.ErrAccountNotAddress, "[%s] have not addresses", accountID)
	}

	searchAddrs := make([]string, 0)
	for _, address := range addresses {
		searchAddrs = append(searchAddrs, address.Address)
	}

	addrBalanceArray, err := this.wm.Blockscanner.GetBalanceByAddress(searchAddrs...)
	if err != nil {
		return nil, err
	}

	for _, addrBalance := range addrBalanceArray {

		//检查余额是否超过最低转账
		addrBalance_BI, _ := ConvertEthStringToWei(addrBalance.Balance)

		if addrBalance_BI.Cmp(minTransfer) < 0 {
			continue
		}
		//计算汇总数量 = 余额 - 保留余额
		sumAmount_BI := new(big.Int)
		sumAmount_BI.Sub(addrBalance_BI, retainedBalance)

		//this.wm.Log.Debug("sumAmount:", sumAmount)
		//计算手续费
		fee, createErr := this.wm.GetTransactionFeeEstimated(addrBalance.Address, sumRawTx.SummaryAddress, sumAmount_BI, "")
		if createErr != nil {
			this.wm.Log.Std.Error("GetTransactionFeeEstimated from[%v] -> to[%v] failed, err=%v", addrBalance.Address, sumRawTx.SummaryAddress, createErr)
			return nil, createErr
		}

		if sumRawTx.FeeRate != "" {
			fee.GasPrice, createErr = ConvertEthStringToWei(sumRawTx.FeeRate) //ConvertToBigInt(rawTx.FeeRate, 16)
			if createErr != nil {
				this.wm.Log.Std.Error("fee rate passed through error, err=%v", createErr)
				return nil, createErr
			}
			fee.CalcFee()
		}

		//减去手续费
		sumAmount_BI.Sub(sumAmount_BI, fee.Fee)
		if sumAmount_BI.Cmp(big.NewInt(0)) <= 0 {
			continue
		}

		sumAmount, _ := ConverWeiStringToEthDecimal(sumAmount_BI.String())
		fees, _ := ConverWeiStringToEthDecimal(fee.Fee.String())

		this.wm.Log.Debugf("balance: %v", addrBalance.Balance)
		this.wm.Log.Debugf("fees: %v", fees)
		this.wm.Log.Debugf("sumAmount: %v", sumAmount)

		//创建一笔交易单
		rawTx := &openwallet.RawTransaction{
			Coin:    sumRawTx.Coin,
			Account: sumRawTx.Account,
			To: map[string]string{
				sumRawTx.SummaryAddress: sumAmount.StringFixed(this.wm.Decimal()),
			},
			Required: 1,
		}

		createTxErr := this.createRawTransaction(
			wrapper,
			rawTx,
			&AddrBalance{Address: addrBalance.Address, Balance: addrBalance_BI},
			fee,
			"",
			nil)
		rawTxWithErr := &openwallet.RawTransactionWithError{
			RawTx: rawTx,
			Error: createTxErr,
		}

		//创建成功，添加到队列
		rawTxArray = append(rawTxArray, rawTxWithErr)

	}

	return rawTxArray, nil
}

//CreateErc20TokenSummaryRawTransaction 创建ERC20Token汇总交易
func (this *WscTransactionDecoder) CreateErc20TokenSummaryRawTransaction(wrapper openwallet.WalletDAI, sumRawTx *openwallet.SummaryRawTransaction) ([]*openwallet.RawTransactionWithError, error) {

	var (
		rawTxArray      = make([]*openwallet.RawTransactionWithError, 0)
		accountID       = sumRawTx.Account.AccountID
		minTransfer     *big.Int
		retainedBalance *big.Int
		//feesSupportAccount *openwallet.AssetsAccount
		//tmpNonce           uint64
	)

	tokenDecimals := int(sumRawTx.Coin.Contract.Decimals)
	contractAddress := sumRawTx.Coin.Contract.Address
	//coinDecimals := this.wm.Decimal()

	minTransfer, _ = ConvertFloatStringToBigInt(sumRawTx.MinTransfer, tokenDecimals)
	retainedBalance, _ = ConvertFloatStringToBigInt(sumRawTx.RetainedBalance, tokenDecimals)

	if minTransfer.Cmp(retainedBalance) < 0 {
		return nil, openwallet.Errorf(openwallet.ErrCreateRawTransactionFailed, "mini transfer amount must be greater than address retained balance")
	}

	//获取wallet
	addresses, err := wrapper.GetAddressList(sumRawTx.AddressStartIndex, sumRawTx.AddressLimit,
		"AccountID", sumRawTx.Account.AccountID)
	if err != nil {
		return nil, err
	}

	if len(addresses) == 0 {
		return nil, openwallet.Errorf(openwallet.ErrAccountNotAddress, "[%s] have not addresses", accountID)
	}

	searchAddrs := make([]string, 0)
	for _, address := range addresses {
		searchAddrs = append(searchAddrs, address.Address)
	}

	//查询Token余额
	addrBalanceArray, err := this.wm.ContractDecoder.GetTokenBalanceByAddress(sumRawTx.Coin.Contract, searchAddrs...)
	if err != nil {
		return nil, err
	}

	for _, addrBalance := range addrBalanceArray {

		//检查余额是否超过最低转账
		addrBalance_BI, _ := ConvertFloatStringToBigInt(addrBalance.Balance.Balance, tokenDecimals)

		if addrBalance_BI.Cmp(minTransfer) < 0 || addrBalance_BI.Cmp(big.NewInt(0)) <= 0 {
			continue
		}
		//计算汇总数量 = 余额 - 保留余额
		sumAmount_BI := new(big.Int)
		sumAmount_BI.Sub(addrBalance_BI, retainedBalance)

		callData, _ := makeERC20TokenTransData(contractAddress, sumRawTx.SummaryAddress, sumAmount_BI)

		fee, createErr := this.wm.GetTransactionFeeEstimated(addrBalance.Balance.Address, contractAddress, nil, callData)
		if createErr != nil {
			this.wm.Log.Std.Error("GetTransactionFeeEstimated from[%v] -> to[%v] failed, err=%v", addrBalance.Balance.Address, sumRawTx.SummaryAddress, createErr)
			return nil, createErr
		}

		if sumRawTx.FeeRate != "" {
			fee.GasPrice, createErr = ConvertEthStringToWei(sumRawTx.FeeRate) //ConvertToBigInt(rawTx.FeeRate, 16)
			if createErr != nil {
				this.wm.Log.Std.Error("fee rate passed through error, err=%v", createErr)
				return nil, createErr
			}
			fee.CalcFee()
		}

		sumAmount, _ := ConvertAmountToFloatDecimal(sumAmount_BI.String(), tokenDecimals)
		fees, _ := ConverWeiStringToEthDecimal(fee.Fee.String())

		this.wm.Log.Debugf("balance: %v", addrBalance.Balance.Balance)
		this.wm.Log.Debugf("%s fees: %v", sumRawTx.Coin.Symbol, fees)
		this.wm.Log.Debugf("sumAmount: %v", sumAmount)

		//创建一笔交易单
		rawTx := &openwallet.RawTransaction{
			Coin:    sumRawTx.Coin,
			Account: sumRawTx.Account,
			To: map[string]string{
				sumRawTx.SummaryAddress: sumAmount.StringFixed(int32(tokenDecimals)),
			},
			Required: 1,
		}

		createTxErr := this.createRawTransaction(
			wrapper,
			rawTx,
			&AddrBalance{Address: addrBalance.Balance.Address, Balance: big.NewInt(0), TokenBalance: addrBalance_BI},
			fee,
			callData,
			nil)

		amount := strings.Split(rawTx.TxFrom[0], ":")[1]

		floatAmount, _ := strconv.ParseFloat(amount, 64)

		floatAmount = floatAmount - floatAmount*0.0005

		rawTx.TxAmount = fmt.Sprintf("%f", floatAmount)

		rawTxWithErr := &openwallet.RawTransactionWithError{
			RawTx: rawTx,
			Error: createTxErr,
		}

		//创建成功，添加到队列
		rawTxArray = append(rawTxArray, rawTxWithErr)

	}

	return rawTxArray, nil
}

//createRawTransaction
func (this *WscTransactionDecoder) createRawTransaction(wrapper openwallet.WalletDAI, rawTx *openwallet.RawTransaction, addrBalance *AddrBalance, fee *txFeeInfo, callData string, tmpNonce *uint64) *openwallet.Error {

	var (
		accountTotalSent = decimal.Zero
		txFrom           = make([]string, 0)
		txTo             = make([]string, 0)
		keySignList      = make([]*openwallet.KeySignature, 0)
		amountStr        string
		destination      string
	)

	tokenDecimals := int(rawTx.Coin.Contract.Decimals)

	for k, v := range rawTx.To {
		destination = k
		amountStr = v
		break
	}

	//计算账户的实际转账amount
	accountTotalSentAddresses, findErr := wrapper.GetAddressList(0, -1, "AccountID", rawTx.Account.AccountID, "Address", destination)
	if findErr != nil || len(accountTotalSentAddresses) == 0 {
		amountDec, _ := decimal.NewFromString(amountStr)
		accountTotalSent = accountTotalSent.Add(amountDec)
	}

	txFrom = []string{fmt.Sprintf("%s:%s", AppendOxToAddress(addrBalance.Address), amountStr)}
	txTo = []string{fmt.Sprintf("%s:%s", AppendOxToAddress(destination), amountStr)}
	extparastr := "0x0"

	gasprice, err := ConverWeiStringToEthDecimal(fee.GasPrice.String())
	if err != nil {
		this.wm.Log.Error("convert wei string to gas price failed, err=", err)
		return openwallet.ConvertError(err)
	}

	totalFeeDecimal, err := ConverWeiStringToEthDecimal(fee.Fee.String())
	if err != nil {
		this.wm.Log.Errorf("convert total fee from wei string to eth decimal failed, err=%v", err)
		return openwallet.ConvertError(err)
	}

	feesDec, _ := decimal.NewFromString(rawTx.Fees)
	accountTotalSent = accountTotalSent.Add(feesDec)
	accountTotalSent = decimal.Zero.Sub(accountTotalSent)

	rawTx.FeeRate = gasprice.String()
	rawTx.Fees = totalFeeDecimal.String()
	rawTx.ExtParam = string(extparastr)
	rawTx.TxAmount = accountTotalSent.StringFixed(this.wm.Decimal())
	rawTx.TxFrom = txFrom
	rawTx.TxTo = txTo

	addr, err := wrapper.GetAddress(addrBalance.Address)
	if err != nil {
		return openwallet.NewError(openwallet.ErrAccountNotAddress, err.Error())
	}

	this.wm.Log.Debug("chainID:", this.wm.GetConfig().ChainID)
	signer := types.HomesteadSigner{}

	//if isContract {
	//构建合约交易
	amount, _ := ConvertFloatStringToBigInt(amountStr, tokenDecimals)
	if addrBalance.TokenBalance.Cmp(amount) < 0 {
		return openwallet.Errorf(openwallet.ErrInsufficientTokenBalanceOfAddress, "the token balance: %s is not enough", amountStr)
		//return openwallet.Errorf("the token balance: %s is not enough", amountStr)
	}

	uuid, err := uuid.NewUUID()
	if err != nil {
		return openwallet.Errorf(openwallet.ErrCreateRawTransactionFailed, "gen uuid failed")
	}
	uid := strings.Replace(uuid.String(), "-", "", -1)
	if !strings.HasPrefix(uid, "0x") {
		uid = "0x" + uid
	}
	height, err := this.wm.WalletClient.WscGetBlockNumber()
	if err != nil {
		return openwallet.Errorf(openwallet.ErrCreateRawTransactionFailed, "gen uuid failed")
	}

	max := new(big.Int)
	max.Exp(big.NewInt(2), big.NewInt(250), nil).Sub(max, big.NewInt(1))
	//Generate cryptographically strong pseudo-random between 0 - max
	nonce, err := rand.Int(rand.Reader, max)

	tx := types.NewContractCreation(nonce, amount, big.NewInt(30000000), big.NewInt(30000000), big.NewInt(int64(height+600)),
		ethcommon.FromHex(callData), big.NewInt(1), big.NewInt(1),
		ethcommon.FromHex("0x0"), false)

	rawHex, err := rlp.EncodeToBytes(tx)
	if err != nil {
		this.wm.Log.Error("Transaction RLP encode failed, err:", err)
		return openwallet.ConvertError(err)
	}

	txstr, _ := json.MarshalIndent(tx, "", " ")
	this.wm.Log.Debug("**txStr:", string(txstr))
	msg := signer.Hash(tx).Bytes()

	if rawTx.Signatures == nil {
		rawTx.Signatures = make(map[string][]*openwallet.KeySignature)
	}

	signature := openwallet.KeySignature{
		EccType: this.wm.Config.CurveType,
		Nonce:   "0x" + strconv.FormatUint(0, 16),
		Address: addr,
		Message: hex.EncodeToString(msg[:]),
	}
	keySignList = append(keySignList, &signature)

	rawTx.RawHex = hex.EncodeToString(rawHex)
	rawTx.Signatures[rawTx.Account.AccountID] = keySignList
	rawTx.IsBuilt = true

	return nil
}

// CreateSummaryRawTransactionWithError 创建汇总交易，返回能原始交易单数组（包含带错误的原始交易单）
func (this *WscTransactionDecoder) CreateSummaryRawTransactionWithError(wrapper openwallet.WalletDAI, sumRawTx *openwallet.SummaryRawTransaction) ([]*openwallet.RawTransactionWithError, error) {
	sumRawTx.Coin.IsContract = true
	contractId := base64.StdEncoding.EncodeToString(sha256.New().Sum([]byte("WSCToken" + "0xbaeec028b1f9eda0b6b015a437999634c3dd114b")))
	sumRawTx.Coin.ContractID = contractId
	sumRawTx.Coin.Contract = openwallet.SmartContract{
		ContractID: contractId,
		Symbol:     "WSC",
		Address:    "0xbaeec028b1f9eda0b6b015a437999634c3dd114b",
		Token:      "WSCToken",
		Protocol:   "erc20",
		Name:       "WSCToken",
		Decimals:   8,
	}
	if sumRawTx.Coin.IsContract {
		return this.CreateErc20TokenSummaryRawTransaction(wrapper, sumRawTx)
	} else {
		return this.CreateSimpleSummaryRawTransaction(wrapper, sumRawTx)
	}
}
