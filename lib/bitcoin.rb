require 'bitcoin/version'
require 'eventmachine'
require 'ecdsa'
require 'securerandom'
require 'json'
require 'bech32'
require 'ffi'
require_relative 'openassets'

module Bitcoin

  autoload :Util, 'bitcoin/util'
  autoload :ChainParams, 'bitcoin/chain_params'
  autoload :Message, 'bitcoin/message'
  autoload :Logger, 'bitcoin/logger'
  autoload :Block, 'bitcoin/block'
  autoload :BlockHeader, 'bitcoin/block_header'
  autoload :Tx, 'bitcoin/tx'
  autoload :Script, 'bitcoin/script/script'
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
  autoload :Opcodes, 'bitcoin/opcodes'
  autoload :Node, 'bitcoin/node'
  autoload :Base58, 'bitcoin/base58'
  autoload :Secp256k1, 'bitcoin/secp256k1'
  autoload :Mnemonic, 'bitcoin/mnemonic'
  autoload :ValidationState, 'bitcoin/validation'
  autoload :Network, 'bitcoin/network'
  autoload :Store, 'bitcoin/store'
  autoload :RPC, 'bitcoin/rpc'

  require_relative 'bitcoin/constants'

  extend Util

  @chain_param = :mainnet

  # set bitcoin network chain params
  def self.chain_params=(name)
    raise "chain params for #{name} is not defined." unless %i(mainnet testnet regtest).include?(name.to_sym)
    @current_chain = nil
    @chain_param = name.to_sym
  end

  # current bitcoin network chain params.
  def self.chain_params
    return @current_chain if @current_chain
    case @chain_param
    when :mainnet
      Bitcoin::ChainParams.mainnet
    when :testnet
      Bitcoin::ChainParams.testnet
    when :regtest
      Bitcoin::ChainParams.regtest
    end
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

  class ::String
    # binary convert to hex string
    def bth
      unpack('H*').first
    end

    # hex string convert to binary
    def htb
      [self].pack('H*')
    end

    # get opcode
    def opcode
      case encoding
      when Encoding::ASCII_8BIT
        each_byte.next
      when Encoding::US_ASCII
        ord
      else
        to_i
      end
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
      instance_variables.inject({}) do |result, var|
        key = var.to_s
        key.slice!(0) if key.start_with?('@')
        value = instance_variable_get(var)
        if value.is_a?(Array)
          result.update(key => value.map{|v|v.to_h})
        else
          result.update(key => value)
        end
      end
    end

  end

end
