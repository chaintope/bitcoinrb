require 'leveldb'

module Bitcoin
  module Store

    autoload :DB, 'bitcoin/store/db'
    autoload :SPVChainStore, 'bitcoin/store/spv_chain_store'
    autoload :ChainEntry, 'bitcoin/store/chain_entry'

  end
end