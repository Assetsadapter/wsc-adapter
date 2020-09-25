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

import "testing"

func TestWalletManager_GetTokenBalanceByAddress(t *testing.T) {
	tm := NewWalletManager()
	baseAPI := "http://chain3.wscbank.com:9000"
	client := &Client{BaseURL: baseAPI, Debug: true}
	tm.WalletClient = client
	tm.Config.ChainID = 1

	addrs := []AddrBalanceInf{
		&AddrBalance{Address: "0x709971d6e9e70ad45df87f34375baa5a22a1f929", Index: 0},
	}

	err := tm.GetTokenBalanceByAddress("0xbaeec028b1f9eda0b6b015a437999634c3dd114b", addrs...)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}
}
