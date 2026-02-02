module Bitcoin
  module Message

    class Error < StandardError; end

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
    autoload :CmpctBlock, 'bitcoin/message/cmpct_block'
    autoload :HeaderAndShortIDs, 'bitcoin/message/header_and_short_ids'
    autoload :PrefilledTx, 'bitcoin/message/prefilled_tx'
    autoload :GetBlockTxn, 'bitcoin/message/get_block_txn'
    autoload :BlockTransactionRequest, 'bitcoin/message/block_transaction_request'
    autoload :BlockTxn, 'bitcoin/message/block_txn'
    autoload :BlockTransactions, 'bitcoin/message/block_transactions'
    autoload :GetCFilters, 'bitcoin/message/get_cfilters'
    autoload :GetCFHeaders, 'bitcoin/message/get_cfheaders'
    autoload :CFParser, 'bitcoin/message/cf_parser'
    autoload :GetCFCheckpt, 'bitcoin/message/get_cfcheckpt'
    autoload :CFCheckpt, 'bitcoin/message/cfcheckpt'
    autoload :CFilter, 'bitcoin/message/cfilter'
    autoload :CFHeaders, 'bitcoin/message/cfheaders'
    autoload :SendAddrV2, 'bitcoin/message/send_addr_v2'
    autoload :AddrV2, 'bitcoin/message/addr_v2'
    autoload :WTXIDRelay, 'bitcoin/message/wtxid_relay'
    autoload :SendTxRcncl, 'bitcoin/message/send_tx_rcncl'

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
        compact_witness: 70015,
        wtxid_relay: 70016
    }

    module_function

    # Decode P2P message.
    # @param [String] command P2P message command string.
    # @param [String] payload P2P message payload with hex format..
    # @return [Bitcoin::Message]
    def decode(command, payload = nil)
      payload = payload.htb if payload
      case command
      when Version::COMMAND
        Version.parse_from_payload(payload)
      when VerAck::COMMAND
        VerAck.new
      when GetAddr::COMMAND
        GetAddr.new
      when Addr::COMMAND
        Addr.parse_from_payload(payload)
      when SendHeaders::COMMAND
        SendHeaders.new
      when FeeFilter::COMMAND
        FeeFilter.parse_from_payload(payload)
      when Ping::COMMAND
        Ping.parse_from_payload(payload)
      when Pong::COMMAND
        Pong.parse_from_payload(payload)
      when GetHeaders::COMMAND
        GetHeaders.parse_from_payload(payload)
      when Headers::COMMAND
        Headers.parse_from_payload(payload)
      when Block::COMMAND
        Block.parse_from_payload(payload)
      when Tx::COMMAND
        Tx.parse_from_payload(payload)
      when NotFound::COMMAND
        NotFound.parse_from_payload(payload)
      when MemPool::COMMAND
        MemPool.new
      when Reject::COMMAND
        Reject.parse_from_payload(payload)
      when SendCmpct::COMMAND
        SendCmpct.parse_from_payload(payload)
      when Inv::COMMAND
        Inv.parse_from_payload(payload)
      when MerkleBlock::COMMAND
        MerkleBlock.parse_from_payload(payload)
      when CmpctBlock::COMMAND
        CmpctBlock.parse_from_payload(payload)
      when GetData::COMMAND
        GetData.parse_from_payload(payload)
      when GetCFHeaders::COMMAND
        GetCFHeaders.parse_from_payload(payload)
      when GetCFilters::COMMAND
        GetCFilters.parse_from_payload(payload)
      when GetCFCheckpt::COMMAND
        GetCFCheckpt.parse_from_payload(payload)
      when CFCheckpt::COMMAND
        CFCheckpt.parse_from_payload(payload)
      when CFHeaders::COMMAND
        CFHeaders.parse_from_payload(payload)
      when CFilter::COMMAND
        CFilter.parse_from_payload(payload)
      when SendAddrV2::COMMAND
        SendAddrV2.new
      when AddrV2::COMMAND
        AddrV2.parse_from_payload(payload)
      when WTXIDRelay::COMMAND
        WTXIDRelay.new
      when SendTxRcncl::COMMAND
        SendTxRcncl.parse_from_payload(payload)
      end
    end

  end
end
