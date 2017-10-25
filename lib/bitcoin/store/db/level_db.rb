require 'leveldb'

module Bitcoin
  module Store
    module DB

      class LevelDB

        attr_reader :db
        attr_reader :logger

        def initialize(path = "#{Bitcoin.base_dir}/db/spv")
          # @logger = Bitcoin::Logger.create(:debug)
          FileUtils.mkdir_p(path)
          @db = ::LevelDB::DB.new(path)
          # logger.debug 'Opened LevelDB successfully.'
        end

        # put data into LevelDB.
        # @param [Object] key a key.
        # @param [Object] value a value.
        def put(key, value)
          # logger.debug "put #{key} data"
          db.put(key, value)
        end

        # get value from specified key.
        # @param [Object] key a key.
        # @return[Object] the stored value.
        def get(key)
          db.get(key)
        end

        # get best block hash.
        def best_hash
          db.get(KEY_PREFIX[:best])
        end

        # delete specified key data.
        def delete(key)
          db.delete(key)
        end

        # get block hash specified +height+
        def get_hash_from_height(height)
          db.get(height_key(height))
        end

        # get next block hash specified +hash+
        def next_hash(hash)
          db.get(KEY_PREFIX[:next] + hash)
        end

        # get entry payload
        # @param [String] hash the hash with hex format.
        # @return [String] the ChainEntry payload.
        def get_entry_payload_from_hash(hash)
          db.get(KEY_PREFIX[:entry] + hash)
        end

        def save_entry(entry)
          db.batch do
            db.put(entry.key ,entry.to_payload)
            db.put(height_key(entry.height), entry.hash)
            connect_entry(entry)
          end
        end

        def close
          db.close
        end

        private

        # generate height key
        def height_key(height)
          KEY_PREFIX[:height] + height.to_s(16).htb.reverse.bth
        end

        def connect_entry(entry)
          unless entry.genesis?
            tip_block = Bitcoin::Store::ChainEntry.parse_from_payload(get_entry_payload_from_hash(best_hash))
            unless tip_block.hash == entry.prev_hash
              raise "entry(#{entry.hash}) does not reference current best block hash(#{tip_block.hash})"
            end
            unless tip_block.height + 1 == entry.height
              raise "block height is small than current best block."
            end
          end
          db.put(KEY_PREFIX[:best], entry.hash)
          db.put(KEY_PREFIX[:next] + entry.prev_hash, entry.hash)
        end
      end

    end
  end
end