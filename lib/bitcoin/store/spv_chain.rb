module Bitcoin

  module Store

    KEY_PREFIX = {
        entry: 'e',   # key: block hash, value: Bitcoin::Store::ChainEntry payload
        height: 'h',  # key: block height, value: block hash.
        best: 'B',    # value: best block hash.
        next: 'n'     # key: block hash, value: A hash of the next block of the specified hash
    }

    class SPVChain

      attr_reader :db
      attr_reader :logger

      def initialize(db = Bitcoin::Store::DB::LevelDB.new)
        @db = db # TODO multiple db switch
        @logger = Bitcoin::Logger.create(:debug)
        initialize_block
      end

      # get latest block in the store.
      # @return[Bitcoin::Store::ChainEntry]
      def latest_block
        hash = db.best_hash
        return nil unless hash
        find_entry_by_hash(hash)
      end

      # find block entry with the specified height.
      def find_entry_by_height(height)
        find_entry_by_hash(db.get_hash_from_height(height))
      end

      # find block entry with the specified hash
      def find_entry_by_hash(hash)
        payload = db.get_entry_payload_from_hash(hash)
        ChainEntry.parse_from_payload(payload)
      end

      # append block header to chain.
      # @param [Bitcoin::BlockHeader] header a block header.
      # @return [Bitcoin::Store::ChainEntry] appended block header entry.
      def append_header(header)
        logger.debug("append header #{header.hash}")
        raise "this header is invalid. #{header.hash}" unless header.valid?
        best_block = latest_block
        current_height = best_block.height
        unless best_block.hash == header.prev_hash
          # TODO implements recovery process
          raise "header's previous hash(#{header.prev_hash}) does not match current best block's(#{best_block.hash})."
        else
          entry = Bitcoin::Store::ChainEntry.new(header, current_height + 1)
          db.save_entry(entry)
          entry
        end
      end

      # get next block hash for specified +hash+
      # @param [String] hash the block hash
      # @return [String] the next block hash. If it does not exist yet, return nil.
      def next_hash(hash)
        db.next_hash(hash)
      end

      # get median time past for specified block +hash+
      # @param [String] hash the block hash.
      # @return [Integer] the median time past value.
      def mtp(hash)
        time = []
        Bitcoin::MEDIAN_TIME_SPAN.times do
          entry = find_entry_by_hash(hash)
          time << entry.header.time
          hash = entry.header.prev_hash
        end
        time.sort!
        time[time.size / 2]
      end

      private

      # if database is empty, put genesis block.
      def initialize_block
        unless latest_block
          block = Bitcoin.chain_params.genesis_block
          genesis = ChainEntry.new(block.header, 0)
          db.save_entry(genesis)
        end
      end

    end

  end

end