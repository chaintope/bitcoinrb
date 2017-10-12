module Bitcoin

  module Store

    KEY_PREFIX = {
        entry: 'e',   # key: block hash, value: Bitcoin::Store::ChainEntry payload
        height: 'h',  # key: block height, value: block hash.
        best: 'B'     # value: best block hash.
    }

    class SPVChain

      attr_reader :db

      def initialize(db = Bitcoin::Store::DB::LevelDB.new)
        @db = db # TODO multiple db switch
        initialize_block
      end

      # get latest block in the store.
      # @return[Bitcoin::Store::ChainEntry]
      def latest_block
        hash = db.get(KEY_PREFIX[:best])
        return nil unless hash
        find_entry_by_hash(hash)
      end

      # find block entry with the specified height.
      def find_entry_by_height(height)
        hash = db.get(height_key(height))
        find_entry_by_hash(hash)
      end

      # find block entry with the specified hash
      def find_entry_by_hash(hash)
        payload = db.get(KEY_PREFIX[:entry] + hash)
        puts "payload = #{payload.bth}"
        ChainEntry.parse_from_payload(payload)
      end

      # save block
      def save_block(entry)
        db.put(entry.key ,entry.to_payload)
        db.put(height_key(entry.height), entry.hash)
        connect_block(entry)
      end

      private

      # if database is empty, put genesis block.
      def initialize_block
        unless latest_block
          block = Bitcoin.chain_params.genesis_block
          genesis = ChainEntry.new(block.header, 0)
          save_block(genesis)
        end
      end

      # generate height key
      def height_key(height)
        KEY_PREFIX[:height] + height.to_s(16).htb.reverse.bth
      end

      # connect a block to chain.
      def connect_block(entry)
        unless entry.genesis?
          tip_block = find_entry_by_hash(db.get(KEY_PREFIX[:best]))
          unless tip_block.hash == entry.prev_hash
            raise "entry(#{entry.hash}) does not reference current best block hash(#{tip_block.hash})"
          end
          raise "block height is small than current best block." if tip_block.height > entry.height
        end
        db.put(KEY_PREFIX[:best], entry.hash)
      end

    end

  end

end