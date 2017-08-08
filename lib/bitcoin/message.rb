module Bitcoin
  module Message

    autoload :Handler, 'bitcoin/message/handler'
    autoload :Base, 'bitcoin/message/base'
    autoload :Inventory, 'bitcoin/message/inventory'
    autoload :InventoriesParser, 'bitcoin/message/inventories_parser'
    autoload :HeadersParser, 'bitcoin/message/headers_parser'
    autoload :Version, 'bitcoin/message/version'
    autoload :VerAck, 'bitcoin/message/ver_ack'
    autoload :Addr, 'bitcoin/message/addr'
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

    HEADER_SIZE = 24
    USER_AGENT = "/bitcoinrb:#{Bitcoin::VERSION}/"

    SERVICE_FLAGS = {none: 0, network: 1 << 0, getutxo: 1 << 1, bloom: 1 << 2, witness: 1 << 3, xthin: 1 << 4}

    DEFAULT_STOP_HASH = "00"*32

  end
end
