// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/systemcontracts"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
)

// StateProcessor is a basic Processor, which takes care of transitioning
// state from one point to another.
//
// StateProcessor implements Processor.
type StateProcessor struct {
	config *params.ChainConfig // Chain configuration options
	bc     *BlockChain         // Canonical block chain
	engine consensus.Engine    // Consensus engine used for block rewards
}

// NewStateProcessor initialises a new StateProcessor.
func NewStateProcessor(config *params.ChainConfig, bc *BlockChain, engine consensus.Engine) *StateProcessor {
	return &StateProcessor{
		config: config,
		bc:     bc,
		engine: engine,
	}
}

// Process processes the state changes according to the Ethereum rules by running
// the transaction messages using the statedb and applying any rewards to both
// the processor (coinbase) and any included uncles.
//
// Process returns the receipts and logs accumulated during the process and
// returns the amount of gas that was used in the process. If any of the
// transactions failed to execute due to insufficient gas it will return an error.
func (p *StateProcessor) Process(block *types.Block, statedb *state.StateDB, cfg vm.Config) (*state.StateDB, types.Receipts, []*types.Log, uint64, error) {
	var (
		usedGas     = new(uint64)
		header      = block.Header()
		blockHash   = block.Hash()
		blockNumber = block.Number()
		allLogs     []*types.Log
		gp          = new(GasPool).AddGas(block.GasLimit())
	)

	var receipts = make([]*types.Receipt, 0)
	// Mutate the block and state according to any hard-fork specs
	if p.config.DAOForkSupport && p.config.DAOForkBlock != nil && p.config.DAOForkBlock.Cmp(block.Number()) == 0 {
		misc.ApplyDAOHardFork(statedb)
	}
	// Handle upgrade build-in system contract code
	lastBlock := p.bc.GetBlockByHash(block.ParentHash())
	if lastBlock == nil {
		return statedb, nil, nil, 0, fmt.Errorf("could not get parent block")
	}
	systemcontracts.UpgradeBuildInSystemContract(p.config, blockNumber, lastBlock.Time(), block.Time(), statedb)

	var (
		context = NewEVMBlockContext(header, p.bc, nil)
		vmenv   = vm.NewEVM(context, vm.TxContext{}, statedb, p.config, cfg)
		signer  = types.MakeSigner(p.config, header.Number, header.Time)
		txNum   = len(block.Transactions())
	)
	// Iterate over and process the individual transactions
	posa, isPoSA := p.engine.(consensus.PoSA)
	commonTxs := make([]*types.Transaction, 0, txNum)

	// initialise bloom processors
	bloomProcessors := NewAsyncReceiptBloomGenerator(txNum)
	statedb.MarkFullProcessed()

	// usually do have two tx, one for validator set contract, another for system reward contract.
	systemTxs := make([]*types.Transaction, 0, 2)

	for i, tx := range block.Transactions() {
		if isPoSA {
			if isSystemTx, err := posa.IsSystemTransaction(tx, block.Header()); err != nil {
				bloomProcessors.Close()
				return statedb, nil, nil, 0, err
			} else if isSystemTx {
				systemTxs = append(systemTxs, tx)
				continue
			}
		}

		msg, err := TransactionToMessage(tx, signer, header.BaseFee)
		if err != nil {
			bloomProcessors.Close()
			return statedb, nil, nil, 0, err
		}
		statedb.SetTxContext(tx.Hash(), i)

		receipt, err := applyTransaction(msg, p.config, gp, statedb, blockNumber, blockHash, tx, usedGas, vmenv, bloomProcessors)
		if err != nil {
			bloomProcessors.Close()
			return statedb, nil, nil, 0, fmt.Errorf("could not apply tx %d [%v]: %w", i, tx.Hash().Hex(), err)
		}
		commonTxs = append(commonTxs, tx)
		receipts = append(receipts, receipt)
	}
	bloomProcessors.Close()

	// Fail if Shanghai not enabled and len(withdrawals) is non-zero.
	withdrawals := block.Withdrawals()
	if len(withdrawals) > 0 && !p.config.IsShanghai(block.Number(), block.Time()) {
		return nil, nil, nil, 0, errors.New("withdrawals before shanghai")
	}

	// Finalize the block, applying any consensus engine specific extras (e.g. block rewards)
	err := p.engine.Finalize(p.bc, header, statedb, &commonTxs, block.Uncles(), withdrawals, &receipts, &systemTxs, usedGas)
	if err != nil {
		return statedb, receipts, allLogs, *usedGas, err
	}
	for _, receipt := range receipts {
		allLogs = append(allLogs, receipt.Logs...)
	}

	return statedb, receipts, allLogs, *usedGas, nil
}

func applyTransaction(
	msg *Message,
	config *params.ChainConfig,
	gp *GasPool,
	statedb *state.StateDB,
	blockNumber *big.Int,
	blockHash common.Hash,
	tx *types.Transaction,
	usedGas *uint64,
	evm *vm.EVM,
	receiptProcessors ...ReceiptProcessor,
) (*types.Receipt, error) {
	// Create a new context to be used in the EVM environment.
	txContext := NewEVMTxContext(msg)
	evm.Reset(txContext, statedb)

	// Apply the transaction to the current state (included in the env).
	result, err := ApplyMessage(evm, msg, gp)
	if err != nil {
		return nil, err
	}

	// Check if the target address is a system contract
	// if msg.To != nil && isSystemContract(msg.To) {
	// Retrieve custom gas fee from the smart contract
	customGasFee, gasErr := getCustomGasFeeFromContract(msg, evm, statedb)

	if gasErr == nil && customGasFee > 0 {
		// Override the gas used with the custom value from the contract
		result.UsedGas = customGasFee
	}
	// }

	// Update the state with pending changes.
	var root []byte
	if config.IsByzantium(blockNumber) {
		statedb.Finalise(true)
	} else {
		root = statedb.IntermediateRoot(config.IsEIP158(blockNumber)).Bytes()
	}
	*usedGas += result.UsedGas

	// Create a new receipt for the transaction, storing the intermediate root and gas used
	receipt := &types.Receipt{
		Type:              tx.Type(),
		PostState:         root,
		CumulativeGasUsed: *usedGas,
		TxHash:            tx.Hash(),
		GasUsed:           result.UsedGas,
	}

	if result.Failed() {
		receipt.Status = types.ReceiptStatusFailed
	} else {
		receipt.Status = types.ReceiptStatusSuccessful
	}

	// If the transaction created a contract, store the creation address in the receipt.
	if msg.To == nil {
		receipt.ContractAddress = crypto.CreateAddress(evm.TxContext.Origin, tx.Nonce())
	}

	// Set the receipt logs and create the bloom filter.
	receipt.Logs = statedb.GetLogs(tx.Hash(), blockNumber.Uint64(), blockHash)
	receipt.BlockHash = blockHash
	receipt.BlockNumber = blockNumber
	receipt.TransactionIndex = uint(statedb.TxIndex())

	for _, receiptProcessor := range receiptProcessors {
		receiptProcessor.Apply(receipt)
	}
	return receipt, err
}

// ApplyTransaction attempts to apply a transaction to the given state database
// and uses the input parameters for its environment. It returns the receipt
// for the transaction, gas used and an error if the transaction failed,
// indicating the block was invalid.
func ApplyTransaction(config *params.ChainConfig, bc ChainContext, author *common.Address, gp *GasPool, statedb *state.StateDB, header *types.Header, tx *types.Transaction, usedGas *uint64, cfg vm.Config, receiptProcessors ...ReceiptProcessor) (*types.Receipt, error) {
	msg, err := TransactionToMessage(tx, types.MakeSigner(config, header.Number, header.Time), header.BaseFee)
	if err != nil {
		return nil, err
	}
	// Create a new context to be used in the EVM environment
	blockContext := NewEVMBlockContext(header, bc, author)
	vmenv := vm.NewEVM(blockContext, vm.TxContext{BlobHashes: tx.BlobHashes()}, statedb, config, cfg)
	defer func() {
		ite := vmenv.Interpreter()
		vm.EVMInterpreterPool.Put(ite)
		vm.EvmPool.Put(vmenv)
	}()
	return applyTransaction(msg, config, gp, statedb, header.Number, header.Hash(), tx, usedGas, vmenv, receiptProcessors...)
}
func isSystemContract(addr *common.Address) bool {
	if addr == nil {
		return false
	}
	systemContracts := []common.Address{
		common.HexToAddress("0x0000000000000000000000000000000000001000"),
		common.HexToAddress("0x0000000000000000000000000000000000001001"),
		common.HexToAddress("0x0000000000000000000000000000000000001002"),
		common.HexToAddress("0x0000000000000000000000000000000000001003"),
		common.HexToAddress("0x0000000000000000000000000000000000001004"),
		common.HexToAddress("0x0000000000000000000000000000000000001005"),
		common.HexToAddress("0x0000000000000000000000000000000000001006"),
		common.HexToAddress("0x0000000000000000000000000000000000001007"),
		common.HexToAddress("0x0000000000000000000000000000000000001008"),
		common.HexToAddress("0x0000000000000000000000000000000000002000"),
		common.HexToAddress("0x0000000000000000000000000000000000002001"),
		common.HexToAddress("0x0000000000000000000000000000000000007777"),
	}
	for _, sc := range systemContracts {
		if *addr == sc {
			return true
		}
	}
	return false
}
func getCustomGasFeeFromContract(msg *Message, evm *vm.EVM, statedb *state.StateDB) (uint64, error) {
	contractAddress := common.HexToAddress("0x0000000000000000000000000000000000007777")
	funcSelector := []byte{0xab, 0xcd, 0xef, 0x12} // Selector for getFeeAmountPerCall

	// Разыменование указателя на адрес назначения
	var toAddress common.Address
	if msg.To != nil {
		toAddress = *msg.To
	} else {
		return 0, fmt.Errorf("destination address is nil")
	}

	// Формирование данных для вызова
	inputData := append(funcSelector, toAddress.Bytes()...)
	inputData = append(inputData, msg.Data[:4]...) // Добавляем селектор функции

	// Преобразование msg.From в vm.AccountRef (реализует ContractRef)
	caller := vm.AccountRef(msg.From)

	// Конвертация баланса в uint64
	balance := new(big.Int).Set(statedb.GetBalance(msg.From))
	if !balance.IsUint64() {
		return 0, fmt.Errorf("balance overflow")
	}
	balanceUint64 := balance.Uint64()

	// Вызов контракта через EVM
	result, _, err := evm.Call(caller, contractAddress, inputData, balanceUint64, msg.Value)
	if err != nil {
		return 0, err // Возврат ошибки, если вызов не удался
	}

	// Преобразование результата вызова в значение комиссии
	fee := new(big.Int).SetBytes(result)
	return fee.Uint64(), nil
}
