module Bitcoin

  COIN = 100_000_000
  MAX_MONEY = 21_000_000 * COIN

  # Byte size of the ripemd160 hash
  RIPEMD160_SIZE = 20
  # Byte size of the SHA256 hash
  SHA256_SIZE = 32
  # Byte size of the HASH160 hash
  HASH160_SIZE = 20
  # Byte size of the HASH256 hash
  HASH256_SIZE = 32
  # Byte size of x-only public key
  X_ONLY_PUBKEY_SIZE = 32

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

  # Min feerate for defining dust.
  DUST_RELAY_TX_FEE = 3000

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
  SCRIPT_VERIFY_CONST_SCRIPTCODE = (1 << 16) # Making OP_CODESEPARATOR and FindAndDelete fail any non-segwit scripts
  SCRIPT_VERIFY_TAPROOT = (1 << 17) # Taproot/Tapscript validation (BIPs 341 & 342)
  SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION = (1 << 18) # Making unknown Taproot leaf versions non-standard
  SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS = (1 << 19) # Making unknown OP_SUCCESS non-standard
  SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE = (1 << 20) # Making unknown public key versions (in BIP 342 scripts) non-standard

  MANDATORY_SCRIPT_VERIFY_FLAGS = SCRIPT_VERIFY_P2SH

  # Standard script verification flags that standard transactions will comply with.
  STANDARD_SCRIPT_VERIFY_FLAGS = [
    MANDATORY_SCRIPT_VERIFY_FLAGS,
    SCRIPT_VERIFY_DERSIG,
    SCRIPT_VERIFY_STRICTENC,
    SCRIPT_VERIFY_MINIMALDATA,
    SCRIPT_VERIFY_NULLDUMMY,
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS,
    SCRIPT_VERIFY_CLEANSTACK,
    SCRIPT_VERIFY_MINIMALIF,
    SCRIPT_VERIFY_NULLFAIL,
    SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY,
    SCRIPT_VERIFY_CHECKSEQUENCEVERIFY,
    SCRIPT_VERIFY_LOW_S,
    SCRIPT_VERIFY_WITNESS,
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
    SCRIPT_VERIFY_WITNESS_PUBKEYTYPE,
    SCRIPT_VERIFY_CONST_SCRIPTCODE,
    SCRIPT_VERIFY_TAPROOT,
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION,
    SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS,
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE
  ].inject(SCRIPT_VERIFY_NONE){|flags, f| flags |= f}

  # for script

  # witness version
  WITNESS_VERSION_V0 = 0x00
  WITNESS_VERSION_V1 = Bitcoin::Opcodes::OP_1

  # Maximum script length in bytes
  MAX_SCRIPT_SIZE = 10000

  # Maximum number of public keys per multisig
  MAX_PUBKEYS_PER_MULTISIG = 20

  # Maximum number of non-push operations per script
  MAX_OPS_PER_SCRIPT = 201

  # Maximum number of bytes pushable to the stack
  MAX_SCRIPT_ELEMENT_SIZE = 520

  # Maximum number of size in the stack
  MAX_STACK_SIZE = 1000

  # Threshold for nLockTime: below this value it is interpreted as block number, otherwise as UNIX timestamp.
  LOCKTIME_THRESHOLD = 500000000

  # Tag for input annex. If there are at least two witness elements for a transaction input,
  # and the first byte of the last element is 0x50, this last element is called annex, and
  # has meanings independent of the script
  ANNEX_TAG = 0x50

  # Validation weight per passing signature (Tapscript only, see BIP 342).
  VALIDATION_WEIGHT_PER_SIGOP_PASSED = 50

  # How much weight budget is added to the witness size (Tapscript only, see BIP 342).
  VALIDATION_WEIGHT_OFFSET = 50

  # Signature hash types/flags
  SIGHASH_TYPE = { all: 0x01, none: 0x02, single: 0x3, anyonecanpay: 0x80 , default: 0}

  # Maximum number length in bytes
  DEFAULT_MAX_NUM_SIZE = 4

  # 80 bytes of data, +1 for OP_RETURN, +2 for the pushdata opcodes.
  MAX_OP_RETURN_RELAY = 83

  # for script error
  SCRIPT_ERR_OK = 0
  SCRIPT_ERR_UNKNOWN_ERROR = 1
  SCRIPT_ERR_EVAL_FALSE = 2
  SCRIPT_ERR_OP_RETURN = 3

  # Max sizes
  SCRIPT_ERR_SCRIPT_SIZE = 10
  SCRIPT_ERR_PUSH_SIZE = 11
  SCRIPT_ERR_OP_COUNT = 12
  SCRIPT_ERR_STACK_SIZE = 13
  SCRIPT_ERR_SIG_COUNT = 14
  SCRIPT_ERR_PUBKEY_COUNT = 15

  # Failed verify operations
  SCRIPT_ERR_VERIFY = 20
  SCRIPT_ERR_EQUALVERIFY = 21
  SCRIPT_ERR_CHECKMULTISIGVERIFY = 22
  SCRIPT_ERR_CHECKSIGVERIFY = 23
  SCRIPT_ERR_NUMEQUALVERIFY = 24

  # Logical/Format/Canonical errors
  SCRIPT_ERR_BAD_OPCODE = 30
  SCRIPT_ERR_DISABLED_OPCODE = 31
  SCRIPT_ERR_INVALID_STACK_OPERATION = 32
  SCRIPT_ERR_INVALID_ALTSTACK_OPERATION = 33
  SCRIPT_ERR_UNBALANCED_CONDITIONAL = 34

  # CHECKLOCKTIMEVERIFY and CHECKSEQUENCEVERIFY
  SCRIPT_ERR_NEGATIVE_LOCKTIME = 40
  SCRIPT_ERR_UNSATISFIED_LOCKTIME = 41

  # Malleability
  SCRIPT_ERR_SIG_HASHTYPE = 50
  SCRIPT_ERR_SIG_DER = 51
  SCRIPT_ERR_MINIMALDATA = 52
  SCRIPT_ERR_SIG_PUSHONLY = 53
  SCRIPT_ERR_SIG_HIGH_S = 54
  SCRIPT_ERR_SIG_NULLDUMMY = 55
  SCRIPT_ERR_PUBKEYTYPE = 56
  SCRIPT_ERR_CLEANSTACK = 57
  SCRIPT_ERR_MINIMALIF = 58
  SCRIPT_ERR_SIG_NULLFAIL = 59

  # softfork safeness
  SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS = 60
  SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM = 61
  SCRIPT_ERR_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION = 62
  SCRIPT_ERR_DISCOURAGE_UNKNOWN_ANNEX = 63
  SCRIPT_ERR_DISCOURAGE_OP_SUCCESS = 64
  SCRIPT_ERR_DISCOURAGE_UPGRADABLE_PUBKEYTYPE = 65

  # segregated witness
  SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH = 70
  SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY = 71
  SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH = 72
  SCRIPT_ERR_WITNESS_MALLEATED = 73
  SCRIPT_ERR_WITNESS_MALLEATED_P2SH = 74
  SCRIPT_ERR_WITNESS_UNEXPECTED = 75
  SCRIPT_ERR_WITNESS_PUBKEYTYPE = 76

  # Constant scriptCode
  SCRIPT_ERR_OP_CODESEPARATOR = 77
  SCRIPT_ERR_SIG_FINDANDDELETE = 78

  SCRIPT_ERR_ERROR_COUNT = 80

  # Taproot
  SCRIPT_ERR_SCHNORR_SIG_SIZE = 90
  SCRIPT_ERR_SCHNORR_SIG_HASHTYPE = 91
  SCRIPT_ERR_SCHNORR_SIG = 92
  SCRIPT_ERR_TAPROOT_WRONG_CONTROL_SIZE = 93
  SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT = 94
  SCRIPT_ERR_TAPSCRIPT_CHECKMULTISIG = 95
  SCRIPT_ERR_TAPSCRIPT_MINIMALIF = 96

  ERRCODES_MAP = Hash[*constants.grep(/^SCRIPT_ERR_/).map { |c| [const_get(c), c.to_s] }.flatten]
  NAME_MAP = Hash[*constants.grep(/^SCRIPT_ERR_/).map { |c| [c.to_s, const_get(c)] }.flatten]

  # witness commitment
  WITNESS_COMMITMENT_HEADER = 'aa21a9ed'

  COINBASE_WTXID = '00'* 32

  # for message
  MESSAGE_HEADER_SIZE = 24

  # for peer
  PARALLEL_THREAD = 3

  # Maximum amount of time that a block timestamp is allowed to exceed the current network-adjusted time before the block will be accepted.
  MAX_FUTURE_BLOCK_TIME = 2 * 60 * 60

  # Size of set to pick median time from.
  MEDIAN_TIME_SPAN = 11

  BIP32_EXTKEY_WITH_VERSION_SIZE = 78

  HARDENED_THRESHOLD = 2147483648 # 2**31

  # Signature hash sizes
  WITNESS_V0_SCRIPTHASH_SIZE = 32
  WITNESS_V0_KEYHASH_SIZE = 20
  WITNESS_V1_TAPROOT_SIZE = 32

  TAPROOT_LEAF_MASK = 0xfe
  TAPROOT_LEAF_TAPSCRIPT = 0xc0
  TAPROOT_CONTROL_BASE_SIZE = 33
  TAPROOT_CONTROL_NODE_SIZE = 32
  TAPROOT_CONTROL_MAX_NODE_COUNT = 128
  TAPROOT_CONTROL_MAX_SIZE = TAPROOT_CONTROL_BASE_SIZE + TAPROOT_CONTROL_NODE_SIZE * TAPROOT_CONTROL_MAX_NODE_COUNT

end