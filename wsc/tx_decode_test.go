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
	"encoding/hex"
	"testing"

	"github.com/Assetsadapter/wsc-adapter/wsc_txsigner/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/tidwall/gjson"
)

func TestNewEthTxExtPara(t *testing.T) {
	extParam := "{\"data\":\"\",\"gasLimit\":\"0\"}"
	extPara := NewEthTxExtPara(gjson.Parse(extParam))
	t.Logf("extPara.GasLimit: %s\n", extPara.GasLimit)
	t.Logf("extPara.Data: %s\n", extPara.Data)
}

func TestWscTransactionDecoder_SignRawTransaction(t *testing.T) {
	msg := "f87c9003eeb72a17c44bf2a72b86194db791bd80830f42408301fdf194baeec028b1f9eda0b6b015a437999634c3dd114b80b844a9059cbb000000000000000000000000709971d6e9e70ad45df87f34375baa5a22a1f9290000000000000000000000000000000000000000000000000000000005f5e1000101001c8080"
	_, err := hex.DecodeString(msg)
	if err != nil {
		t.Fatalf("decode string failed %s", err.Error())
	}
}

func TestWscTransactionDecoder_CreateErc20TokenRawTransaction(t *testing.T) {
	//callData, _ := makeERC20TokenTransData("0xbaeec028b1f9eda0b6b015a437999634c3dd114b", "", big.NewInt(100000000))
	tx := types.NewTransaction(0, 1000000, 130545, 0, 1,
		1, common.FromHex("0x2cad21c4c195485e8a3547a5ea145566"),
		common.FromHex("0xa9059cbb000000000000000000000000709971d6e9e70ad45df87f34375baa5a22a1f9290000000000000000000000000000000000000000000000000000000005f5e100"),
		common.FromHex("0x0"), common.HexToAddress("0xbaeec028b1f9eda0b6b015a437999634c3dd114b"))
	rawTx, _ := rlp.EncodeToBytes(tx)
	println(hex.EncodeToString(rawTx))
}

func TestNewTransactionDecoder(t *testing.T) {
	gasLimit := []byte{15, 66, 64}
	println("gasLimit: 2  --- " + hex.EncodeToString(gasLimit))
	blockLimit := []byte{1, 253, 241}
	println("blockLimit: 3 --- " + hex.EncodeToString(blockLimit))
	toAddress := []byte{186, 238, 192, 40, 177, 249, 237, 160, 182, 176, 21, 164, 55, 153, 150, 52, 195, 221, 17, 75}
	println("toAddress: 4 --- " + hex.EncodeToString(toAddress))
	data := []byte{169, 5, 156, 187, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 112, 153, 113, 214, 233, 231, 10, 212, 93, 248, 127, 52, 55, 91, 170, 90, 34, 161, 249, 41, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 245, 225, 0}
	println("data : 5  --- " + hex.EncodeToString(data))
}
