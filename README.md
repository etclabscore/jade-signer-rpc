# Jade Signer RPC

Jade Signer JSON-RPC API lets you manage keys and sign transactions and messages offline for any EVM-based blockchain.

[View The Documentation](https://playground.open-rpc.org/?uiSchema[appBar][ui:title]=Jade%20Signer&uiSchema[appBar][ui:logoUrl]=https://github.com/etclabscore/jade-media-assets/raw/master/jade-logo-light/jade-logo-light%20(PNG)/48x48.png&uiSchema[appBar][ui:input]=false&uiSchema[appBar][ui:splitView]=false&schemaUrl=https://raw.githubusercontent.com/etclabscore/jade-signer-rpc/master/jade-signer-rs/openrpc.json).

## The Problem

Most Existing Ethereum Clients include wallets or signers within the full node. This bloats client software and introduces more surface area for security issues to arise. The signing software should be offline and separate from a full node client to ensure proper separation of concerns.

## The Solution

Jade Signer RPC is a an API to support the generation, import, and/or storing of Ethereum Private Keys. It uses the [Web3 Secret Storage Defition](https://github.com/ethereumproject/wiki/wiki/Web3-Secret-Storage-Definition) to store keys offline and optionally use [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) to generate mnemonic phrases. This software has no access to outside nodes or APIs.

## Usage

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
 SUBCOMMANDS:	
    server         Start local RPC server	
```

## Contributing

How to contribute, build and release are outlined in [CONTRIBUTING.md](CONTRIBUTING.md), [BUILDING.md](BUILDING.md) and [RELEASING.md](RELEASING.md) respectively. Commits in this repository follow the [CONVENTIONAL_COMMITS.md](CONVENTIONAL_COMMITS.md) specification.
