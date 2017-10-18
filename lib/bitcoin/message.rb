module Bitcoin
  module Message

    autoload :Base, 'bitcoin/message/base'
    autoload :Inventory, 'bitcoin/message/inventory'
    autoload :InventoriesParser, 'bitcoin/message/inventories_parser'
    autoload :HeadersParser, 'bitcoin/message/headers_parser'
    autoload :Version, 'bitcoin/message/version'
    autoload :VerAck, 'bitcoin/message/ver_ack'
    autoload :Addr, 'bitcoin/message/addr'
    autoload :NetworkAddr, 'bitcoin/message/network_addr'
    autoload :Block, 'bitcoin/message/block'
    autoload :FilterLoad, 'bitcoin/message/filter_load'
    autoload :FilterAdd, 'bitcoin/message/filter_add'
    autoload :FilterClear, 'bitcoin/message/filter_clear'
    autoload :MerkleBlock, 'bitcoin/message/merkle_block'
    autoload :Tx, 'bitcoin/message/tx'
    autoload :Ping, 'bitcoin/message/ping'
    autoload :Pong, 'bitcoin/message/pong'
    autoload :Inv, 'bitcoin/message/inv'
    autoload :GetBlocks, 'bitcoin/message/get_blocks'
    autoload :GetHeaders, 'bitcoin/message/get_headers'
    autoload :Headers, 'bitcoin/message/headers'
    autoload :GetAddr, 'bitcoin/message/get_addr'
    autoload :GetData, 'bitcoin/message/get_data'
    autoload :SendHeaders, 'bitcoin/message/send_headers'
    autoload :FeeFilter, 'bitcoin/message/fee_filter'
    autoload :MemPool, 'bitcoin/message/mem_pool'
    autoload :NotFound, 'bitcoin/message/not_found'
    autoload :Error, 'bitcoin/message/error'
    autoload :Reject, 'bitcoin/message/reject'
    autoload :SendCmpct, 'bitcoin/message/send_cmpct'

    USER_AGENT = "/bitcoinrb:#{Bitcoin::VERSION}/"

    SERVICE_FLAGS = {
        none: 0,
        network: 1 << 0,  # the node is capable of serving the block chain. It is currently set by all Bitcoin Core node, and is unset by SPV clients or other peers that just want network services but don't provide them.
        # getutxo: 1 << 1, # BIP-64. not implemented in Bitcoin Core.
        bloom: 1 << 2,    # the node is capable and willing to handle bloom-filtered connections. Bitcoin Core node used to support this by default, without advertising this bit, but no longer do as of protocol version 70011 (= NO_BLOOM_VERSION)
        witness: 1 << 3,  # the node can be asked for blocks and transactions including witness data.
        # xthin: 1 << 4 # support Xtreme Thinblocks. not implemented in Bitcoin Core
    }

    # DEFAULT_SERVICE_FLAGS = SERVICE_FLAGS[:network] | SERVICE_FLAGS[:bloom] | SERVICE_FLAGS[:witness]

    DEFAULT_SERVICE_FLAGS = SERVICE_FLAGS[:none] | SERVICE_FLAGS[:witness]

    DEFAULT_STOP_HASH = "00"*32

    # the protocol version.
    VERSION = {
        headers: 31800,
        pong: 60001,
        bloom: 70011,
        send_headers: 70012,
        fee_filter: 70013,
        compact: 70014,
        compact_witness: 70015
    }

  end
end
