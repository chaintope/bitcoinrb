# Porting part of the code from bitcoin-ruby. see the license.
# https://github.com/lian/bitcoin-ruby/blob/master/COPYING

require 'bitcoin/version'
require 'eventmachine'
require 'schnorr'
require 'securerandom'
require 'json'
require 'bech32'
require 'ffi'
require 'observer'
require 'tmpdir'
require_relative 'openassets'

module Bitcoin

  autoload :Ext, 'bitcoin/ext'
  autoload :Util, 'bitcoin/util'
  autoload :ChainParams, 'bitcoin/chain_params'
  autoload :Message, 'bitcoin/message'
  autoload :Logger, 'bitcoin/logger'
  autoload :Block, 'bitcoin/block'
  autoload :BlockHeader, 'bitcoin/block_header'
  autoload :Tx, 'bitcoin/tx'
  autoload :Script, 'bitcoin/script/script'
  autoload :Multisig, 'bitcoin/script/multisig'
  autoload :ScriptInterpreter, 'bitcoin/script/script_interpreter'
  autoload :ScriptError, 'bitcoin/script/script_error'
  autoload :TxChecker, 'bitcoin/script/tx_checker'
  autoload :TxIn, 'bitcoin/tx_in'
  autoload :TxOut, 'bitcoin/tx_out'
  autoload :OutPoint, 'bitcoin/out_point'
  autoload :ScriptWitness, 'bitcoin/script_witness'
  autoload :MerkleTree, 'bitcoin/merkle_tree'
  autoload :Key, 'bitcoin/key'
  autoload :ExtKey, 'bitcoin/ext_key'
  autoload :ExtPubkey, 'bitcoin/ext_key'
  autoload :Opcodes, 'bitcoin/opcodes'
  autoload :Node, 'bitcoin/node'
  autoload :Base58, 'bitcoin/base58'
  autoload :Secp256k1, 'bitcoin/secp256k1'
  autoload :Mnemonic, 'bitcoin/mnemonic'
  autoload :ValidationState, 'bitcoin/validation'
  autoload :Network, 'bitcoin/network'
  autoload :Store, 'bitcoin/store'
  autoload :RPC, 'bitcoin/rpc'
  autoload :Wallet, 'bitcoin/wallet'
  autoload :BloomFilter, 'bitcoin/bloom_filter'
  autoload :Payments, 'bitcoin/payments'
  autoload :PSBT, 'bitcoin/psbt'
  autoload :GCSFilter, 'bitcoin/gcs_filter'
  autoload :BlockFilter, 'bitcoin/block_filter'
  autoload :BitStreamWriter, 'bitcoin/bit_stream'
  autoload :BitStreamReader, 'bitcoin/bit_stream'
  autoload :KeyPath, 'bitcoin/key_path'
  autoload :Descriptor, 'bitcoin/descriptor'
  autoload :SLIP39, 'bitcoin/slip39'
  autoload :Aezeed, 'bitcoin/aezeed'
  autoload :PaymentCode, 'bitcoin/payment_code'
  autoload :BIP85Entropy, 'bitcoin/bip85_entropy'
  autoload :Errors, 'bitcoin/errors'
  autoload :SigHashGenerator, 'bitcoin/sighash_generator'

  require_relative 'bitcoin/constants'
  require_relative 'bitcoin/ext/ecdsa'

  extend Util

  @chain_param = :mainnet

  # set bitcoin network chain params
  def self.chain_params=(name)
    raise "chain params for #{name} is not defined." unless %i(mainnet testnet regtest signet).include?(name.to_sym)
    @current_chain = nil
    @chain_param = name.to_sym
  end

  # current bitcoin network chain params.
  def self.chain_params
    return @current_chain if @current_chain
    case @chain_param
    when :mainnet
      @current_chain = Bitcoin::ChainParams.mainnet
    when :testnet
      @current_chain = Bitcoin::ChainParams.testnet
    when :regtest
      @current_chain = Bitcoin::ChainParams.regtest
    when :signet
      @current_chain = Bitcoin::ChainParams.signet
    end
    @current_chain
  end

  # base dir path that store blockchain data and wallet data
  def self.base_dir
    "#{Dir.home}/.bitcoinrb/#{@chain_param}"
  end

  # get secp implementation module
  def self.secp_impl
    path = ENV['SECP256K1_LIB_PATH']
    (path && File.exist?(path)) ? Bitcoin::Secp256k1::Native : Bitcoin::Secp256k1::Ruby
  end

  def self.hmac_sha512(key, data)
    OpenSSL::HMAC.digest(OpenSSL::Digest.new('SHA512'), key, data)
  end

  def self.hmac_sha256(key, data)
    OpenSSL::HMAC.digest(OpenSSL::Digest.new('SHA256'), key, data)
  end

  class ::String
    # binary convert to hex string
    def bth
      unpack1('H*')
    end

    # hex string convert to binary
    def htb
      [self].pack('H*')
    end

    # binary convert to integer
    def bti
      bth.to_i(16)
    end

    # reverse hex string endian
    def rhex
      htb.reverse.bth
    end

    # get opcode
    def opcode
      force_encoding(Encoding::ASCII_8BIT).ord
    end

    def opcode?
      !pushdata?
    end

    def push_opcode?
      [Bitcoin::Opcodes::OP_PUSHDATA1, Bitcoin::Opcodes::OP_PUSHDATA2, Bitcoin::Opcodes::OP_PUSHDATA4].include?(opcode)
    end

    # whether data push only?
    def pushdata?
      opcode <= Bitcoin::Opcodes::OP_PUSHDATA4 && opcode > Bitcoin::Opcodes::OP_0
    end

    def pushed_data
      return nil unless pushdata?
      offset = 1
      case opcode
      when Bitcoin::Opcodes::OP_PUSHDATA1
        offset += 1
      when Bitcoin::Opcodes::OP_PUSHDATA2
        offset += 2
      when Bitcoin::Opcodes::OP_PUSHDATA4
        offset += 4
      end
      self[offset..-1]
    end

    def valid_pushdata_length?
      buf = StringIO.new(self)
      opcode = buf.read(1).ord
      offset = 1
      return false if buf.eof?
      len = case opcode
            when Bitcoin::Opcodes::OP_PUSHDATA1
              offset += 1
              buf.read(1).unpack1('C')
            when Bitcoin::Opcodes::OP_PUSHDATA2
              offset += 2
              buf.read(2).unpack1('v')
            when Bitcoin::Opcodes::OP_PUSHDATA4
              offset += 4
              buf.read(4).unpack1('V')
            else
              opcode
            end
      self.bytesize == len + offset
    end

    # whether value is hex or not hex
    # @return [Boolean] return true if data is hex
    def valid_hex?
      !self[/\H/]
    end

  end

  class ::Object

    def build_json
      if self.is_a?(Array)
        "[#{self.map{|o|o.to_h.to_json}.join(',')}]"
      else
        to_h.to_json
      end
    end

    def to_h
      return self if self.is_a?(String)
      instance_variables.inject({}) do |result, var|
        key = var.to_s
        key.slice!(0) if key.start_with?('@')
        value = instance_variable_get(var)
        if value.is_a?(Array)
          result.update(key => value.map{|v|v.to_h})
        else
          result.update(key => value.class.to_s.start_with?("Bitcoin::") ? value.to_h : value)
        end
      end
    end

  end

  class ::Integer
    def to_even_length_hex
      hex = to_s(16)
      hex.rjust((hex.length / 2.0).ceil * 2, '0')
    end

    def itb
      to_even_length_hex.htb
    end

    # convert bit string
    def to_bits(length = nil )
      if length
        to_s(2).rjust(length, '0')
      else
        to_s(2)
      end
    end
  end

end
