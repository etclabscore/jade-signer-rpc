# Jade Signer RPC

Jade Signer JSON-RPC API lets you manage keys and sign transactions and messages offline for any EVM-based blockchain.

[View The Documentation](https://playground.open-rpc.org/?uiSchema[appBar][ui:splitView]=false&schemaUrl=https://raw.githubusercontent.com/etclabscore/jade-signer-rpc/master/signer/openrpc.json&uiSchema[appBar][ui:logoUrl]=https://avatars1.githubusercontent.com/u/45863699?s=200&v=4).

# The Problem

Most Existing Ethereum Clients include wallets or signers within the full node. This bloats client software and introduces more surface area for security issues to arise. The signing software should be offline and separate from a full node client to ensure proper separation of concerns.

# The Solution

Jade Signer RPC is a an API to support the generation, import, and/or storing of Ethereum Private Keys. It uses the [Web3 Secret Storage Defition](https://github.com/ethereumproject/wiki/wiki/Web3-Secret-Storage-Definition) to store keys offline and optionally use [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) to generate mnemonic phrases. This software has no access to outside nodes or APIs.

# Usage

```shell	
$ jade-signer-rpc --help	
 jade-signer-rpc	
Command-line interface for Jade Signer RPC
 USAGE:	
    jade-signer-rpc [FLAGS] [OPTIONS] [SUBCOMMAND]	
 FLAGS:	
    -h, --help       Prints help information	
    -v               Sets the level of verbosity	
    -V, --version    Display version	
 OPTIONS:	
    -p, --base-path <base-path>    Set path for chain storage	
    -c, --chain <chain>            Sets a chain name [default: etc-main]	
 SUBCOMMANDS:	
    server         Start local RPC server	
```
