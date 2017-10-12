require 'leveldb'

module Bitcoin
  module Store

    autoload :DB, 'bitcoin/store/db'
    autoload :SPVChain, 'bitcoin/store/spv_chain'
    autoload :ChainEntry, 'bitcoin/store/chain_entry'

  end
end