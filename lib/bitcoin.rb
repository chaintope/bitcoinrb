require 'bitcoin/version'
require 'eventmachine'
require 'securerandom'
require 'json'
require 'bech32'

module Bitcoin

  autoload :Util, 'bitcoin/util'
  autoload :ChainParams, 'bitcoin/chain_params'
  autoload :Message, 'bitcoin/message'
  autoload :Connection, 'bitcoin/connection'
  autoload :Logger, 'bitcoin/logger'
  autoload :BlockHeader, 'bitcoin/block_header'
  autoload :Tx, 'bitcoin/tx'
  autoload :Script, 'bitcoin/script/script'
  autoload :ScriptInterpreter, 'bitcoin/script/script_interpreter'
  autoload :ScriptError, 'bitcoin/script/script_error'
  autoload :TxIn, 'bitcoin/tx_in'
  autoload :TxOut, 'bitcoin/tx_out'
  autoload :OutPoint, 'bitcoin/out_point'
  autoload :ScriptWitness, 'bitcoin/script_witness'
  autoload :MerkleTree, 'bitcoin/merkle_tree'
  autoload :Key, 'bitcoin/key'
  autoload :Opcodes, 'bitcoin/opcodes'
  autoload :Node, 'bitcoin/nodes'
  autoload :Base58, 'bitcoin/base58'
  autoload :Secp256k1, 'bitcoin/secp256k1'

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
    "#{Dir.home}/.bitcoinrb"
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
      d = case encoding
            when Encoding::ASCII_8BIT
              each_byte.next
            when Encoding::US_ASCII
              ord
            else
              to_i
          end
      Bitcoin::Opcodes.defined?(d) ? d : nil
    end

    # whether data push only?
    def pushdata?
      d = case encoding
          when Encoding::ASCII_8BIT
            each_byte.next
          when Encoding::US_ASCII
            ord
          else
            to_i
          end
      OP_0 < d && d <= OP_PUSHDATA4
    end

  end

end
