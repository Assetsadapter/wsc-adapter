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

	//"log"
	"math/big"
	"sort"
	"strconv"
	"strings"

	"time"

	tool "github.com/blocktree/openwallet/common"
	"github.com/blocktree/openwallet/log"
	"github.com/blocktree/openwallet/openwallet"

	"github.com/imroc/req"
	"github.com/tidwall/gjson"
)

type Client struct {
	BaseURL string
	Debug   bool
}

type Response struct {
	Id      int         `json:"id"`
	Version string      `json:"jsonrpc"`
	Result  interface{} `json:"result"`
}

/*
1. eth block example
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

type WscBlock struct {
	BlockHeader
	Transactions []BlockTransaction `json:"transactions"`
}

func (this *WscBlock) CreateOpenWalletBlockHeader() *openwallet.BlockHeader {
	header := &openwallet.BlockHeader{
		Hash:              this.BlockHash,
		Previousblockhash: this.PreviousHash,
		Height:            this.BlockHeight,
		Time:              uint64(time.Now().Unix()),
	}
	return header
}

func (this *WscBlock) Init() error {
	var err error
	this.BlockHeight, err = strconv.ParseUint(removeOxFromHex(this.BlockNumber), 16, 64) //ConvertToBigInt(this.BlockNumber, 16) //
	if err != nil {
		log.Errorf("init blockheight failed, err=%v", err)
		return err
	}

	// 加载到账地址, 到账金额， 需要在交易的input中解析
	for i, transaction := range this.Transactions {
		this.Transactions[i].To = "0x" + transaction.Data[34:74]
		this.Transactions[i].Value = "0x" + transaction.Data[74:]
	}
	return nil
}

type TxpoolContent struct {
	Pending map[string]map[string]BlockTransaction `json:"pending"`
}

func (this *TxpoolContent) GetSequentTxNonce(addr string) (uint64, uint64, uint64, error) {
	txpool := this.Pending
	var target map[string]BlockTransaction
	/*if _, exist := txpool[addr]; !exist {
		return 0, 0, 0, nil
	}
	if txpool[addr] == nil {
		return 0, 0, 0, nil
	}

	if len(txpool[addr]) == 0 {
		return 0, 0, 0, nil
	}*/
	for theAddr, _ := range txpool {
		//log.Debugf("theAddr:%v, addr:%v", strings.ToLower(theAddr), strings.ToLower(addr))
		if strings.ToLower(theAddr) == strings.ToLower(addr) {
			target = txpool[theAddr]
		}
	}

	nonceList := make([]interface{}, 0)
	for n, _ := range target {
		tn, err := strconv.ParseUint(n, 10, 64)
		if err != nil {
			log.Error("parse nonce[", n, "] in txpool to uint faile, err=", err)
			return 0, 0, 0, err
		}
		nonceList = append(nonceList, tn)
	}

	sort.Slice(nonceList, func(i, j int) bool {
		if nonceList[i].(uint64) < nonceList[j].(uint64) {
			return true
		}
		return false
	})

	var min, max, count uint64
	for i := 0; i < len(nonceList); i++ {
		if i == 0 {
			min = nonceList[i].(uint64)
			max = min
			count++
		} else if nonceList[i].(uint64) != max+1 {
			break
		} else {
			max++
			count++
		}
	}
	return min, max, count, nil
}

func (this *TxpoolContent) GetPendingTxCountForAddr(addr string) int {
	txpool := this.Pending
	if _, exist := txpool[addr]; !exist {
		return 0
	}
	if txpool[addr] == nil {
		return 0
	}
	return len(txpool[addr])
}

func (this *Client) ethGetTransactionCount(addr string) (uint64, error) {
	params := []interface{}{
		AppendOxToAddress(addr),
		"pending",
	}

	result, err := this.Call("eth_getTransactionCount", 1, params)
	if err != nil {
		//errInfo := fmt.Sprintf("get block[%v] failed, err = %v \n", blockNumStr,  err)
		log.Errorf("get transaction count failed, err = %v \n", err)
		return 0, err
	}

	if result.Type != gjson.String {
		log.Errorf("result type failed. ")
		return 0, errors.New("result type failed. ")
	}

	//blockNum, err := ConvertToBigInt(result.String(), 16)
	nonceStr := result.String()
	nonceStr = strings.ToLower(nonceStr)
	nonceStr = removeOxFromHex(nonceStr)
	nonce, err := strconv.ParseUint(nonceStr, 16, 64)
	if err != nil {
		log.Errorf("parse nounce failed, err=%v", err)
		return 0, err
	}
	return nonce, nil
}

func (this *Client) EthGetTxPoolContent() (*TxpoolContent, error) {
	result, err := this.Call("txpool_content", 1, nil)
	if err != nil {
		//errInfo := fmt.Sprintf("get block[%v] failed, err = %v \n", blockNumStr,  err)
		log.Errorf("get tx pool failed, err = %v \n", err)
		return nil, err
	}

	if result.Type != gjson.JSON {
		errInfo := fmt.Sprintf("get tx pool content failed, result type is %v", result.Type)
		log.Errorf(errInfo)
		return nil, errors.New(errInfo)
	}

	var txpool TxpoolContent

	err = json.Unmarshal([]byte(result.Raw), &txpool)
	if err != nil {
		log.Errorf("decode json [%v] failed, err=%v", []byte(result.Raw), err)
		return nil, err
	}

	return &txpool, nil
}

func (this *Client) WscGetTransactionReceipt(transactionId string) (*EthTransactionReceipt, error) {
	params := []interface{}{
		1,
		transactionId,
	}

	var txReceipt EthTransactionReceipt
	result, err := this.Call("getTransactionReceipt", 1, params)
	if err != nil {
		//errInfo := fmt.Sprintf("get block[%v] failed, err = %v \n", blockNumStr,  err)
		log.Errorf("get tx[%v] receipt failed, err = %v \n", transactionId, err)
		return nil, err
	}

	if result.Type != gjson.JSON {
		errInfo := fmt.Sprintf("get tx[%v] receipt result type failed, result type is %v", transactionId, result.Type)
		log.Errorf(errInfo)
		return nil, errors.New(errInfo)
	}

	err = json.Unmarshal([]byte(result.Raw), &txReceipt)
	if err != nil {
		log.Errorf("decode json [%v] failed, err=%v", []byte(result.Raw), err)
		return nil, err
	}

	return &txReceipt, nil

}

func (this *Client) ethGetBlockSpecByHash(blockHash string, showTransactionSpec bool) (*WscBlock, error) {
	params := []interface{}{
		blockHash,
		showTransactionSpec,
	}
	var ethBlock WscBlock

	result, err := this.Call("eth_getBlockByHash", 1, params)
	if err != nil {
		//errInfo := fmt.Sprintf("get block[%v] failed, err = %v \n", blockNumStr,  err)
		log.Errorf("get block[%v] failed, err = %v \n", blockHash, err)
		return nil, err
	}

	if result.Type != gjson.JSON {
		errInfo := fmt.Sprintf("get block[%v] result type failed, result type is %v", blockHash, result.Type)
		log.Errorf(errInfo)
		return nil, errors.New(errInfo)
	}

	err = json.Unmarshal([]byte(result.Raw), &ethBlock)
	if err != nil {
		log.Errorf("decode json [%v] failed, err=%v", []byte(result.Raw), err)
		return nil, err
	}

	err = ethBlock.Init()
	if err != nil {
		log.Errorf("init eth block failed, err=%v", err)
		return nil, err
	}
	return &ethBlock, nil
}

func (this *Client) EthGetTransactionByHash(txid string) (*BlockTransaction, error) {
	params := []interface{}{
		AppendOxToAddress(txid),
	}

	var tx BlockTransaction

	result, err := this.Call("eth_getTransactionByHash", 1, params)
	if err != nil {
		//errInfo := fmt.Sprintf("get block[%v] failed, err = %v \n", blockNumStr,  err)
		log.Errorf("get transaction[%v] failed, err = %v \n", AppendOxToAddress(txid), err)
		return nil, err
	}

	if result.Type != gjson.JSON {
		errInfo := fmt.Sprintf("get transaction[%v] result type failed, result type is %v", AppendOxToAddress(txid), result.Type)
		log.Errorf(errInfo)
		return nil, errors.New(errInfo)
	}

	err = json.Unmarshal([]byte(result.Raw), &tx)
	if err != nil {
		log.Errorf("decode json [%v] failed, err=%v", result.Raw, err)
		return nil, err
	}

	return &tx, nil
}

func (this *Client) wscGetBlockSpecByBlockNum2(blockNum string, showTransactionSpec bool) (*WscBlock, error) {
	params := []interface{}{
		1,
		blockNum,
		showTransactionSpec,
	}
	var ethBlock WscBlock

	result, err := this.Call("getBlockByNumber", 1, params)
	if err != nil {
		//errInfo := fmt.Sprintf("get block[%v] failed, err = %v \n", blockNumStr,  err)
		log.Errorf("get block[%v] failed, err = %v \n", blockNum, err)
		return nil, err
	}

	if showTransactionSpec {
		err = json.Unmarshal([]byte(result.Raw), &ethBlock)
	} else {
		err = json.Unmarshal([]byte(result.Raw), &ethBlock.BlockHeader)
	}
	if err != nil {
		log.Errorf("decode json [%v] failed, err=%v", result.Raw, err)
		return nil, err
	}

	err = ethBlock.Init()
	if err != nil {
		log.Errorf("init eth block failed, err=%v", err)
		return nil, err
	}
	return &ethBlock, nil
}

func (this *Client) WscGetBlockSpecByBlockNum(blockNum uint64, showTransactionSpec bool) (*WscBlock, error) {
	blockNumStr := "0x" + strconv.FormatUint(blockNum, 16)
	return this.wscGetBlockSpecByBlockNum2(blockNumStr, showTransactionSpec)
}

func (this *Client) ethGetTxpoolStatus() (uint64, uint64, error) {
	result, err := this.Call("txpool_status", 1, nil)
	if err != nil {
		//errInfo := fmt.Sprintf("get block[%v] failed, err = %v \n", blockNumStr,  err)
		//log.Errorf("get block[%v] failed, err = %v \n", err)
		return 0, 0, err
	}

	type TxPoolStatus struct {
		Pending string `json:"pending"`
		Queued  string `json:"queued"`
	}

	txStatusResult := TxPoolStatus{}
	err = json.Unmarshal([]byte(result.Raw), &txStatusResult)
	if err != nil {
		log.Errorf("decode from json failed, err=%v", err)
		return 0, 0, err
	}

	pendingNum, err := strconv.ParseUint(removeOxFromHex(txStatusResult.Pending), 16, 64)
	if err != nil {
		log.Errorf("convert txstatus pending number to uint failed, err=%v", err)
		return 0, 0, err
	}

	queuedNum, err := strconv.ParseUint(removeOxFromHex(txStatusResult.Queued), 16, 64)
	if err != nil {
		log.Errorf("convert queued number to uint failed, err=%v", err)
		return 0, 0, err
	}

	return pendingNum, queuedNum, nil
}

type SolidityParam struct {
	ParamType  string
	ParamValue interface{}
}

func makeRepeatString(c string, count uint) string {
	cs := make([]string, 0)
	for i := 0; i < int(count); i++ {
		cs = append(cs, c)
	}
	return strings.Join(cs, "")
}

func makeTransactionData(methodId string, params []SolidityParam) (string, error) {

	data := methodId
	for i, _ := range params {
		var param string
		if params[i].ParamType == SOLIDITY_TYPE_ADDRESS {
			param = strings.ToLower(params[i].ParamValue.(string))
			if strings.Index(param, "0x") != -1 {
				param = tool.Substr(param, 2, len(param))
			}

			if len(param) != 40 {
				return "", errors.New("length of address error.")
			}
			param = makeRepeatString("0", 24) + param
		} else if params[i].ParamType == SOLIDITY_TYPE_UINT256 {
			intParam := params[i].ParamValue.(*big.Int)
			param = intParam.Text(16)
			l := len(param)
			if l > 64 {
				return "", errors.New("integer overflow.")
			}
			param = makeRepeatString("0", uint(64-l)) + param
			//fmt.Println("makeTransactionData intParam:", intParam.String(), " param:", param)
		} else {
			return "", errors.New("not support solidity type")
		}

		data += param
	}
	return data, nil
}

func (this *Client) ERC20GetAddressBalance2(address string, contractAddr string, sign string) (*big.Int, error) {
	if sign != "latest" && sign != "pending" {
		return nil, errors.New("unknown sign was put through.")
	}
	contractAddr = "0x" + strings.TrimPrefix(contractAddr, "0x")
	var funcParams []SolidityParam
	funcParams = append(funcParams, SolidityParam{
		ParamType:  SOLIDITY_TYPE_ADDRESS,
		ParamValue: address,
	})
	trans := make(map[string]interface{})
	data, err := makeTransactionData(ETH_GET_TOKEN_BALANCE_METHOD, funcParams)
	if err != nil {
		log.Errorf("make transaction data failed, err = %v", err)
		return nil, err
	}
	trans["from"] = contractAddr
	trans["to"] = contractAddr
	trans["data"] = data
	params := []interface{}{
		1,
		trans,
	}
	result, err := this.Call("call", 1, params)
	if err != nil {
		log.Errorf(fmt.Sprintf("get addr[%v] erc20 balance failed, err=%v\n", address, err))
		return big.NewInt(0), err
	}
	if result.Type != gjson.JSON {
		errInfo := fmt.Sprintf("get addr[%v] erc20 balance result type error, result type is %v\n", address, result.Type)
		log.Errorf(errInfo)
		return big.NewInt(0), errors.New(errInfo)
	}

	balance, err := ConvertToBigInt(result.Get("output").String(), 16)
	if err != nil {
		errInfo := fmt.Sprintf("convert addr[%v] erc20 balance format to bigint failed, response is %v, and err = %v\n", address, result.String(), err)
		log.Errorf(errInfo)
		return big.NewInt(0), errors.New(errInfo)
	}
	return balance, nil

}

func (this *Client) ERC20GetAddressBalance(address string, contractAddr string) (*big.Int, error) {
	return this.ERC20GetAddressBalance2(address, contractAddr, "pending")
}

func (this *Client) GetAddrBalance2(address string, sign string) (*big.Int, error) {
	if sign != "latest" && sign != "pending" {
		return nil, errors.New("unknown sign was put through.")
	}

	params := []interface{}{
		AppendOxToAddress(address),
		sign,
	}
	result, err := this.Call("eth_getBalance", 1, params)
	if err != nil {
		//log.Errorf(fmt.Sprintf("get addr[%v] balance failed, err=%v\n", address, err))
		return big.NewInt(0), err
	}
	if result.Type != gjson.String {
		errInfo := fmt.Sprintf("get addr[%v] balance result type error, result type is %v\n", address, result.Type)
		log.Errorf(errInfo)
		return big.NewInt(0), errors.New(errInfo)
	}

	balance, err := ConvertToBigInt(result.String(), 16)
	if err != nil {
		errInfo := fmt.Sprintf("convert addr[%v] balance format to bigint failed, response is %v, and err = %v\n", address, result.String(), err)
		log.Errorf(errInfo)
		return big.NewInt(0), errors.New(errInfo)
	}
	return balance, nil
}

func AppendOxToAddress(addr string) string {
	if strings.Index(addr, "0x") == -1 {
		return "0x" + addr
	}
	return addr
}

func makeSimpleTransactionPara(fromAddr *Address, toAddr string, amount *big.Int, password string, fee *txFeeInfo) map[string]interface{} {
	paraMap := make(map[string]interface{})

	//use password to unlock the account
	paraMap["password"] = password
	//use the following attr to eth_sendTransaction
	paraMap["from"] = AppendOxToAddress(fromAddr.Address)
	paraMap["to"] = AppendOxToAddress(toAddr)
	paraMap["value"] = "0x" + amount.Text(16)
	paraMap["gas"] = "0x" + fee.GasLimit.Text(16)
	paraMap["gasPrice"] = "0x" + fee.GasPrice.Text(16)
	return paraMap
}

func makeSimpleTransactiomnPara2(fromAddr string, toAddr string, amount *big.Int, password string) map[string]interface{} {
	paraMap := make(map[string]interface{})
	paraMap["password"] = password
	paraMap["from"] = AppendOxToAddress(fromAddr)
	paraMap["to"] = AppendOxToAddress(toAddr)
	paraMap["value"] = "0x" + amount.Text(16)
	return paraMap
}

func makeSimpleTransGasEstimatedPara(fromAddr string, toAddr string, amount *big.Int) map[string]interface{} {
	//paraMap := make(map[string]interface{})
	//paraMap["from"] = fromAddr
	//paraMap["to"] = toAddr
	//paraMap["value"] = "0x" + amount.Text(16)
	return makeGasEstimatePara(fromAddr, toAddr, amount, "") //araMap
}

func makeERC20TokenTransData(contractAddr string, toAddr string, amount *big.Int) (string, error) {
	var funcParams []SolidityParam
	funcParams = append(funcParams, SolidityParam{
		ParamType:  SOLIDITY_TYPE_ADDRESS,
		ParamValue: toAddr,
	})

	funcParams = append(funcParams, SolidityParam{
		ParamType:  SOLIDITY_TYPE_UINT256,
		ParamValue: amount,
	})

	//fmt.Println("make token transfer data, amount:", amount.String())
	data, err := makeTransactionData(ETH_TRANSFER_TOKEN_BALANCE_METHOD, funcParams)
	if err != nil {
		log.Errorf("make transaction data failed, err = %v", err)
		return "", err
	}
	log.Debugf("data:%v", data)
	return data, nil
}

func makeGasEstimatePara(fromAddr string, toAddr string, value *big.Int, data string) map[string]interface{} {
	paraMap := make(map[string]interface{})
	paraMap["from"] = AppendOxToAddress(fromAddr)
	paraMap["to"] = AppendOxToAddress(toAddr)
	if data != "" {
		paraMap["data"] = data
	}

	if value != nil {
		paraMap["value"] = "0x" + value.Text(16)
	}
	return paraMap
}

func makeERC20TokenTransGasEstimatePara(fromAddr string, contractAddr string, data string) map[string]interface{} {

	//paraMap := make(map[string]interface{})

	//use password to unlock the account
	//use the following attr to eth_sendTransaction
	//paraMap["from"] = fromAddr //fromAddr.Address
	//paraMap["to"] = contractAddr
	//paraMap["value"] = "0x" + amount.Text(16)
	//paraMap["gas"] = "0x" + fee.GasLimit.Text(16)
	//paraMap["gasPrice"] = "0x" + fee.GasPrice.Text(16)
	//paraMap["data"] = data
	return makeGasEstimatePara(fromAddr, contractAddr, nil, data)
}

func (this *Client) ethGetGasEstimated(paraMap map[string]interface{}) (*big.Int, error) {
	trans := make(map[string]interface{})
	var temp interface{}
	var exist bool
	var fromAddr string
	var toAddr string

	if temp, exist = paraMap["from"]; !exist {
		log.Errorf("from not found")
		return big.NewInt(0), errors.New("from not found")
	} else {
		fromAddr = temp.(string)
		trans["from"] = fromAddr
	}

	if temp, exist = paraMap["to"]; !exist {
		log.Errorf("to not found")
		return big.NewInt(0), errors.New("to not found")
	} else {
		toAddr = temp.(string)
		trans["to"] = toAddr
	}

	if temp, exist = paraMap["value"]; exist {
		amount := temp.(string)
		trans["value"] = amount
	}

	if temp, exist = paraMap["data"]; exist {
		data := temp.(string)
		trans["data"] = data
	}

	params := []interface{}{
		trans,
	}

	result, err := this.Call("eth_estimateGas", 1, params)
	if err != nil {
		log.Errorf(fmt.Sprintf("get estimated gas limit from [%v] to [%v] faield, err = %v \n", fromAddr, toAddr, err))
		return big.NewInt(0), err
	}

	if result.Type != gjson.String {
		errInfo := fmt.Sprintf("get estimated gas from [%v] to [%v] result type error, result type is %v\n", fromAddr, toAddr, result.Type)
		log.Errorf(errInfo)
		return big.NewInt(0), errors.New(errInfo)
	}

	gasLimit, err := ConvertToBigInt(result.String(), 16)
	if err != nil {
		errInfo := fmt.Sprintf("convert estimated gas[%v] format to bigint failed, err = %v\n", result.String(), err)
		log.Errorf(errInfo)
		return big.NewInt(0), errors.New(errInfo)
	}
	return gasLimit, nil
}

func makeERC20TokenTransactionPara(fromAddr *Address, contractAddr string, data string,
	password string, fee *txFeeInfo) map[string]interface{} {

	paraMap := make(map[string]interface{})

	//use password to unlock the account
	paraMap["password"] = password
	//use the following attr to eth_sendTransaction
	paraMap["from"] = AppendOxToAddress(fromAddr.Address)
	paraMap["to"] = AppendOxToAddress(contractAddr)
	//paraMap["value"] = "0x" + amount.Text(16)
	paraMap["gas"] = "0x" + fee.GasLimit.Text(16)
	paraMap["gasPrice"] = "0x" + fee.GasPrice.Text(16)
	paraMap["data"] = data
	return paraMap
}

func (this *WalletManager) SendTransactionToAddr(param map[string]interface{}) (string, error) {
	//(addr *Address, to string, amount *big.Int, password string, fee *txFeeInfo) (string, error) {
	var exist bool
	var temp interface{}
	if temp, exist = param["from"]; !exist {
		log.Errorf("from not found.")
		return "", errors.New("from not found.")
	}

	fromAddr := temp.(string)

	if temp, exist = param["password"]; !exist {
		log.Errorf("password not found.")
		return "", errors.New("password not found.")
	}

	password := temp.(string)

	err := this.WalletClient.UnlockAddr(fromAddr, password, 300)
	if err != nil {
		log.Errorf("unlock addr failed, err = %v", err)
		return "", err
	}

	txId, err := this.WalletClient.ethSendTransaction(param)
	if err != nil {
		log.Errorf("ethSendTransaction failed, err = %v", err)
		return "", err
	}

	err = this.WalletClient.LockAddr(fromAddr)
	if err != nil {
		log.Errorf("lock addr failed, err = %v", err)
		return txId, err
	}

	return txId, nil
}

func (this *WalletManager) WscSendRawTransaction(signedTx string) (string, error) {
	return this.WalletClient.wscSendRawTransaction(signedTx)
}

func (this *Client) wscSendRawTransaction(signedTx string) (string, error) {
	params := []interface{}{
		1,
		signedTx,
	}

	result, err := this.Call("sendRawTransaction", 1, params)
	if err != nil {
		log.Errorf(fmt.Sprintf("start raw transaction faield, err = %v \n", err))
		return "", err
	}

	if result.Type != gjson.String {
		log.Errorf("sendRawTransaction result type error")
		return "", errors.New("sendRawTransaction result type error")
	}
	return result.String(), nil
}

func (this *Client) ethSendTransaction(paraMap map[string]interface{}) (string, error) {
	//(fromAddr string, toAddr string, amount *big.Int, fee *txFeeInfo) (string, error) {
	trans := make(map[string]interface{})
	var temp interface{}
	var exist bool
	var fromAddr string
	var toAddr string

	if temp, exist = paraMap["from"]; !exist {
		log.Errorf("from not found")
		return "", errors.New("from not found")
	} else {
		fromAddr = temp.(string)
		trans["from"] = fromAddr
	}

	if temp, exist = paraMap["to"]; !exist {
		log.Errorf("to not found")
		return "", errors.New("to not found")
	} else {
		toAddr = temp.(string)
		trans["to"] = toAddr
	}

	if temp, exist = paraMap["value"]; exist {
		amount := temp.(string)
		trans["value"] = amount
	}

	if temp, exist = paraMap["gas"]; exist {
		gasLimit := temp.(string)
		trans["gas"] = gasLimit
	}

	if temp, exist = paraMap["gasPrice"]; exist {
		gasPrice := temp.(string)
		trans["gasPrice"] = gasPrice
	}

	if temp, exist = paraMap["data"]; exist {
		data := temp.(string)
		trans["data"] = data
	}

	params := []interface{}{
		trans,
	}

	result, err := this.Call("eth_sendTransaction", 1, params)
	if err != nil {
		log.Errorf(fmt.Sprintf("start transaction from [%v] to [%v] faield, err = %v \n", fromAddr, toAddr, err))
		return "", err
	}

	if result.Type != gjson.String {
		log.Errorf("eth_sendTransaction result type error")
		return "", errors.New("eth_sendTransaction result type error")
	}
	return result.String(), nil
}

func (this *Client) ethGetAccounts() ([]string, error) {
	param := make([]interface{}, 0)
	accounts := make([]string, 0)
	result, err := this.Call("eth_accounts", 1, param)
	if err != nil {
		log.Errorf("get eth accounts faield, err = %v \n", err)
		return nil, err
	}

	log.Debugf("result type of eth_accounts is %v", result.Type)

	accountList := result.Array()
	for i, _ := range accountList {
		acc := accountList[i].String()
		accounts = append(accounts, acc)
	}
	return accounts, nil
}

func (this *Client) WscGetBlockNumber() (uint64, error) {
	param := []interface{}{1}
	result, err := this.Call("getBlockNumber", 1, param)
	if err != nil {
		log.Errorf("get block number faield, err = %v \n", err)
		return 0, err
	}

	if result.Type != gjson.String {
		log.Errorf("result of block number type error")
		return 0, errors.New("result of block number type error")
	}

	blockNum, err := ConvertToUint64(result.String(), 16)
	if err != nil {
		log.Errorf("parse block number to big.Int failed, err=%v", err)
		return 0, err
	}

	return blockNum, nil
}

func (this *Client) SerializationTransaction(from, to, amount, blockNum, addr string) (string, error) {
	params := []interface{}{
		1,
		struct {
			From        string `json:"from"`
			To          string `json:"to"`
			BlockNumber string `json:"blockNumber"`
			Address     string `json:"address"`
			Amount      string `json:"amount"`
		}{
			From:        from,
			To:          to,
			Amount:      amount,
			BlockNumber: blockNum,
			Address:     addr,
		},
	}
	result, err := this.Call2("getSerializationTx", 1, params)
	if err != nil {
		return "", err
	}
	if result.Type != gjson.String {
		log.Errorf("result of serialization transaction type error")
		return "", errors.New("result of serialization transaction type error")
	}
	return result.String(), nil
}

func (c *Client) Call(method string, id int64, params []interface{}) (*gjson.Result, error) {
	authHeader := req.Header{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}
	body := make(map[string]interface{}, 0)
	body["jsonrpc"] = "2.0"
	body["id"] = id
	body["method"] = method
	body["params"] = params

	if c.Debug {
		log.Debug("Start Request API...")
	}

	r, err := req.Post(fmt.Sprintf("%s/%s", c.BaseURL, method), req.BodyJSON(&body), authHeader)

	if c.Debug {
		log.Debug("Request API Completed")
	}

	if c.Debug {
		log.Debugf("%+v\n", r)
	}

	if err != nil {
		return nil, err
	}

	resp := gjson.ParseBytes(r.Bytes())
	err = isError(&resp)
	if err != nil {
		return nil, err
	}

	result := resp.Get("result")

	return &result, nil
}

func (c *Client) Call2(method string, id int64, params []interface{}) (*gjson.Result, error) {
	authHeader := req.Header{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}
	body := make(map[string]interface{}, 0)
	body["jsonrpc"] = "2.0"
	body["id"] = id
	body["method"] = method
	body["params"] = params

	if c.Debug {
		log.Debug("Start Request API...")
	}

	r, err := req.Post(fmt.Sprintf("%s/%s", "http://127.0.0.1:9000", method), req.BodyJSON(&body), authHeader)

	if c.Debug {
		log.Debug("Request API Completed")
	}

	if c.Debug {
		log.Debugf("%+v\n", r)
	}

	if err != nil {
		return nil, err
	}

	resp := gjson.ParseBytes(r.Bytes())
	//err = isError(&resp)
	//if err != nil {
	//	return nil, err
	//}
	if err != nil {
		return nil, err
	}

	result := resp.Get("data")

	return &result, nil
}

//isError 是否报错
func isError(result *gjson.Result) error {
	var (
		err error
	)

	if !result.Get("error").IsObject() {

		if !result.Get("result").Exists() {
			return errors.New("Response is empty! ")
		}

		return nil
	}

	errInfo := fmt.Sprintf("[%d]%s",
		result.Get("error.code").Int(),
		result.Get("error.message").String())
	err = errors.New(errInfo)

	return err
}
