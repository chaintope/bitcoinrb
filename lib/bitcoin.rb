require 'bitcoin/version'
require 'eventmachine'
require 'ecdsa'
require 'securerandom'
require 'json'
require 'bech32'
require 'ffi'

module Bitcoin

  COIN = 100_000_000
  MAX_MONEY = 21_000_000 * COIN

  # The maximum allowed size for a serialized block, in bytes (only for buffer size limits)
  MAX_BLOCK_SERIALIZED_SIZE = 4_000_000
  # The maximum allowed weight for a block, see BIP 141 (network rule)
  MAX_BLOCK_WEIGHT = 4_000_000
  # The maximum allowed number of signature check operations in a block (network rule)
  MAX_BLOCK_SIGOPS_COST = 80_000
  # Coinbase transaction outputs can only be spent after this number of new blocks (network rule)
  COINBASE_MATURITY = 100
  WITNESS_SCALE_FACTOR = 4

  # 60 is the lower bound for the size of a valid serialized Tx
  MIN_TRANSACTION_WEIGHT = WITNESS_SCALE_FACTOR * 60
  # 10 is the lower bound for the size of a serialized Tx
  MIN_SERIALIZABLE_TRANSACTION_WEIGHT = WITNESS_SCALE_FACTOR * 10

  # Flags for nSequence and nLockTime locks
  LOCKTIME_VERIFY_SEQUENCE = (1 << 0)
  LOCKTIME_MEDIAN_TIME_PAST = (1 << 1)

  # script verify flags
  SCRIPT_VERIFY_NONE      = 0
  SCRIPT_VERIFY_P2SH      = (1 << 0)
  SCRIPT_VERIFY_STRICTENC = (1 << 1)
  SCRIPT_VERIFY_DERSIG    = (1 << 2)
  SCRIPT_VERIFY_LOW_S     = (1 << 3)
  SCRIPT_VERIFY_NULLDUMMY = (1 << 4)
  SCRIPT_VERIFY_SIGPUSHONLY = (1 << 5)
  SCRIPT_VERIFY_MINIMALDATA = (1 << 6)
  SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS = (1 << 7)
  SCRIPT_VERIFY_CLEANSTACK = (1 << 8)
  SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY = (1 << 9) # Verify CHECKLOCKTIMEVERIFY (BIP-65)
  SCRIPT_VERIFY_CHECKSEQUENCEVERIFY = (1 << 10) # support CHECKSEQUENCEVERIFY opcode (BIP-112)
  SCRIPT_VERIFY_WITNESS = (1 << 11) # Support segregated witness
  SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM = (1 << 12) # Making v1-v16 witness program non-standard
  SCRIPT_VERIFY_MINIMALIF = (1 << 13) # Segwit script only: Require the argument of OP_IF/NOTIF to be exactly 0x01 or empty vector
  SCRIPT_VERIFY_NULLFAIL = (1 << 14) # Signature(s) must be empty vector if an CHECK(MULTI)SIG operation failed
  SCRIPT_VERIFY_WITNESS_PUBKEYTYPE = (1 << 15) # Public keys in segregated witness scripts must be compressed

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
  autoload :TxChecker, 'bitcoin/script/tx_checker'
  autoload :TxIn, 'bitcoin/tx_in'
  autoload :TxOut, 'bitcoin/tx_out'
  autoload :OutPoint, 'bitcoin/out_point'
  autoload :ScriptWitness, 'bitcoin/script_witness'
  autoload :MerkleTree, 'bitcoin/merkle_tree'
  autoload :Key, 'bitcoin/key'
  autoload :ExtKey, 'bitcoin/ext_key'
  autoload :Opcodes, 'bitcoin/opcodes'
  autoload :Node, 'bitcoin/nodes'
  autoload :Base58, 'bitcoin/base58'
  autoload :Secp256k1, 'bitcoin/secp256k1'
  autoload :Mnemonic, 'bitcoin/mnemonic'
  autoload :ValidationState, 'bitcoin/validation'

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

end
