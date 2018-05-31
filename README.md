# Bitcoinrb [![Build Status](https://travis-ci.org/haw-itn/bitcoinrb.svg?branch=master)](https://travis-ci.org/haw-itn/bitcoinrb) [![Gem Version](https://badge.fury.io/rb/bitcoinrb.svg)](https://badge.fury.io/rb/bitcoinrb) [![MIT License](http://img.shields.io/badge/license-MIT-blue.svg?style=flat)](LICENSE) <img src="http://segwit.co/static/public/images/logo.png" width="100">


Bitcoinrb is a Ruby implementation of Bitcoin Protocol.

NOTE: Bitcoinrb work in progress, and there is a possibility of incompatible change. 

## Features

Bitcoinrb supports following feature:

* Bitcoin script interpreter
* De/serialization of Bitcoin protocol network messages
* De/serialization of blocks and transactions
* Key generation and verification for ECDSA, including [BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) and [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) supports.
* Segwit support (parsing segwit payload, Bech32 address, sign for segwit tx, etc..)
* [WIP] SPV node
* [WIP] 0ff-chain protocol

## Requirements

### use Node implementation

If you use node features, please install level DB as follows.

#### install LevelDB

* for Ubuntu

    $ sudo apt-get install libleveldb-dev

+ for Mac

    $ brew install leveldb

and put `leveldb-ruby` in your Gemfile and run bundle install.

```
gem leveldb-ruby
```

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'bitcoinrb'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install bitcoinrb


## Usage

### Chain selection

The parameters of the blockchain are managed by `Bitcoin::ChainParams`. Switch chain parameters as follows:

* mainnet

```ruby
Bitcoin.chain_params = :mainnet
```

This parameter is described in https://github.com/haw-itn/bitcoinrb/blob/master/lib/bitcoin/chainparams/mainnet.yml.

* testnet

```ruby
Bitcoin.chain_params = :testnet
```

This parameter is described in https://github.com/haw-itn/bitcoinrb/blob/master/lib/bitcoin/chainparams/testnet.yml.

* regtest

```ruby
Bitcoin.chain_params = :regtest
```

This parameter is described in https://github.com/haw-itn/bitcoinrb/blob/master/lib/bitcoin/chainparams/regtest.yml.

#### Fork coin

When using with fork coin, please specify the fork_id of the coin as follows.

```ruby
Bitcoin.chain_params.fork_id = 0 # 0 is bch fork id
```

Currently bitcoinrb supports only support and verification of transaction replay protection using `SIGHASH_FORK_ID`.
For details of `SIGHASH_FORK_ID`, refer to the following.

https://github.com/Bitcoin-UAHF/spec/blob/master/replay-protected-sighash.md

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/[USERNAME]/bitcoinrb. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [Contributor Covenant](http://contributor-covenant.org) code of conduct.


## License

The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).

