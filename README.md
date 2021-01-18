# Bitcoinrb [![Build Status](https://travis-ci.org/chaintope/bitcoinrb.svg?branch=master)](https://travis-ci.org/chaintope/bitcoinrb) [![Gem Version](https://badge.fury.io/rb/bitcoinrb.svg)](https://badge.fury.io/rb/bitcoinrb) [![MIT License](http://img.shields.io/badge/license-MIT-blue.svg?style=flat)](LICENSE) <img src="http://segwit.co/static/public/images/logo.png" width="100">


Bitcoinrb is a Ruby implementation of Bitcoin Protocol.

NOTE: Bitcoinrb work in progress, and there is a possibility of incompatible change. 

## Features

Bitcoinrb supports following feature:

* [Bitcoin script interpreter](https://github.com/chaintope/bitcoinrb/wiki/Script)(including [BIP-65](https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki), [BIP-68](https://github.com/bitcoin/bips/blob/master/bip-0068.mediawiki), [BIP-112](https://github.com/bitcoin/bips/blob/master/bip-0112.mediawiki))
* [De/serialization of Bitcoin protocol network messages](https://github.com/chaintope/bitcoinrb/wiki/P2P-Message)
* De/serialization of blocks and [transactions](https://github.com/chaintope/bitcoinrb/wiki/Transaction)
* Key generation and verification for ECDSA, including [BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) and [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) supports.
* ECDSA signature(RFC6979 -Deterministic ECDSA, LOW-S, LOW-R support)
* Segwit support (parsing segwit payload, Bech32 address, sign for segwit tx, [BIP-141](https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki), [BIP-143](https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki), [BIP-144](https://github.com/bitcoin/bips/blob/master/bip-0144.mediawiki))
* [BIP-173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki) Bech32 address support
* [BIP-174](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki) PSBT(Partially Signed Bitcoin Transaction) support
* [BIP-85](https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki) Deterministic Entropy From BIP32 Keychains support by `Bitcoin::BIP85Entropy` class.
* Schnorr signature([BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki))  
* Taproot consensus([BIP-341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki) and [BIP-342](https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki))  
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

and put `leveldb-native` in your Gemfile and run bundle install.

```ruby
gem 'leveldb-native'
```

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'bitcoinrb', require: 'bitcoin'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install bitcoinrb

And then add to your .rb file:

    require 'bitcoin'

## Usage

### Chain selection

The parameters of the blockchain are managed by `Bitcoin::ChainParams`. Switch chain parameters as follows:

* mainnet

```ruby
Bitcoin.chain_params = :mainnet
```

This parameter is described in https://github.com/chaintope/bitcoinrb/blob/master/lib/bitcoin/chainparams/mainnet.yml.

* testnet

```ruby
Bitcoin.chain_params = :testnet
```

This parameter is described in https://github.com/chaintope/bitcoinrb/blob/master/lib/bitcoin/chainparams/testnet.yml.

* regtest

```ruby
Bitcoin.chain_params = :regtest
```

This parameter is described in https://github.com/chaintope/bitcoinrb/blob/master/lib/bitcoin/chainparams/regtest.yml.

* default signet

```ruby
Bitcoin.chain_params = :signet
```

This parameter is described in https://github.com/chaintope/bitcoinrb/blob/master/lib/bitcoin/chainparams/signet.yml.

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/[USERNAME]/bitcoinrb. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [Contributor Covenant](http://contributor-covenant.org) code of conduct.


## License

The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).

