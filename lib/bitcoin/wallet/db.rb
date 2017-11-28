module Bitcoin
  module Wallet

    class DB

      KEY_PREFIX = {
          account: 'a',       # key: account index, value: Account raw data.
          seed: 's',          # value : wallet seed.
      }

      attr_reader :level_db

      def initialize(path = "#{Bitcoin.base_dir}/db/wallet")
        FileUtils.mkdir_p(path)
        @level_db = ::LevelDB::DB.new(path)
      end

      # close database
      def close
        level_db.close
      end

      # get accounts raw data.
      def accounts
        from = KEY_PREFIX[:account] + '00000000'
        to = KEY_PREFIX[:account] + 'ffffffff'
        level_db.each(from: from, to: to).map { |k, v| v}
      end

      def save_account(account)
        level_db.batch do
          key = KEY_PREFIX[:account] + account.index.to_s(16).rjust(8, '0')
          level_db.put(key, account.to_payload)
        end
      end

      # get wallet seed
      def seed
        level_db.get(KEY_PREFIX[:seed])
      end

      # save seed
      def register_seed(seed)
        level_db.put(KEY_PREFIX[:seed], seed)
      end

    end
  end
end