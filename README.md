```shell
                                                   __       __                                  __   __ 
         ___    ____ ___   ___    _____  ____ _   / /  ____/ /        _   __  ____ _  __  __   / /  / /_
        / _ \  / __ `__ \ / _ \  / ___/ / __ `/  / /  / __  /  ______| | / / / __ `/ / / / /  / /  / __/
       /  __/ / / / / / //  __/ / /    / /_/ /  / /  / /_/ /  /_____/| |/ / / /_/ / / /_/ /  / /  / /_  
       \___/ /_/ /_/ /_/ \___/ /_/     \__,_/  /_/   \__,_/          |___/  \__,_/  \__,_/  /_/   \__/  
```
<p align="center">
  <p align="center">
    <a href="https://travis-ci.org/etclabscore/emerald-vault"><img alt="Travis" src="https://travis-ci.org/etclabscore/emerald-vault.svg?branch=master"></a>
    <a href="https://circleci.com/gh/etclabscore/emerald-vault"><img alt="CircleCI" src="https://circleci.com/gh/etclabscore/emerald-vault/tree/master.svg?style=shield"></a>
    <a href="https://ci.appveyor.com/project/etclabscore/emerald-vault">
        <img alt="AppVeyor" src="https://ci.appveyor.com/api/projects/status/e5nqu33xo8y4nk0v?svg=true">
    </a>
    <a href="https://crates.io/crates/emerald-vault"><img alt="crates.io" src="https://img.shields.io/crates/v/emerald-vault.svg?style=flat-square"></a>
    <a href="LICENSE"><img alt="Software License" src="https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=flat-square&maxAge=2592000"></a>
  </p>
</p>

## About

`Emerald Platform` is a set of tools to build and integrate other applications with the Ethereum Classic (ETC) blockchain.
`Emerald Vault` is a tool to access Ethereum ETC from the command line. It connects to an external node (_"upstream"_) and allows a user or application to read information from the blockchain and to send new transactions. In the latter case it provides functionality to sign transactions by a provided Private Key. The tool integrates [emerald-rs](https://github.com/etclabscore/emerald-rs) with the intention of generation, import, and/or storing of Ethereum Private Keys.

`emerald-vault` is compatible with both Ethereum ETC and ETH.


## Usage

```shell
$ emerald-vault --help

emerald-vault
Command-line interface for Emerald platform

USAGE:
    emerald-vault [FLAGS] [OPTIONS] [SUBCOMMAND]

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

For detailed documentation see [https://docs.etclabscore.com/html/emerald-vault](https://docs.etclabscore.com/html/emerald-vault)

## Installing Emerald Vault

### Download stable binary

Binaries for all platforms are currently published at https://github.com/etclabscore/emerald-vault/releases


### Build from sources

#### Requirements

Install Rust from https://www.rust-lang.org/en-US/install.html


Unix one-liner:
```
curl https://sh.rustup.rs -sSf | sh
```

On Windows, Rust additionally requires the C++ build tools for Visual Studio 2013 or later. The easiest way to acquire
the build tools is by installing Microsoft Visual C++ Build Tools 2017 which provides just the Visual C++ build tools.

#### Compile

```
git clone https://github.com/etclabscore/emerald-vault.git
cd emerald-vault
cargo build --release
cd target\debug
```

## Links

- Documentation: https://docs.etclabscore.com/html/emerald-vault
- Issues: https://github.com/etclabscore/emerald-vault/issues
- Development binaries: http://builds.etclabscore.com/


## License

Apache 2.0

