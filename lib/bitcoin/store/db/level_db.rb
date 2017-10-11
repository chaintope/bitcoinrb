require 'leveldb'

module Bitcoin
  module Store
    module DB

      class LevelDB

        attr_reader :db
        attr_reader :logger

        def initialize(path = "#{Bitcoin.base_dir}/db/spv")
          @logger = Bitcoin::Logger.create(:debug)
          FileUtils.mkdir_p(path)
          @db = ::LevelDB::DB.new(path)
          logger.debug 'Opened LevelDB successfully.'
        end

        # put data into LevelDB.
        # @param [Object] key a key.
        # @param [Object] value a value.
        def put(key, value)
          db.put(key, value)
        end

        # get value from specified key.
        # @param [Object] key a key.
        # @return[Object] the stored value.
        def get(key)
          db.get(key)
        end

      end

    end
  end
end