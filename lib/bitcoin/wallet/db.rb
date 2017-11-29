module Bitcoin
  module Wallet

    class DB

      KEY_PREFIX = {
          account: 'a',       # key: account index, value: Account raw data.
          master: 'm',          # value : wallet seed.
      }

      attr_reader :level_db
      attr_accessor :master_key

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

      # get master_key
      def master_key
        @master_key ||= Bitcoin::Wallet::MasterKey.parse_from_payload(level_db.get(KEY_PREFIX[:master]))
      end

      # save seed
      # @param [Bitcoin::Wallet::MasterKey] master a master key.
      def register_master_key(master)
        level_db.put(KEY_PREFIX[:master], master.to_payload)
        @master_key = master
      end

      # whether master key registered.
      def registered_master?
        !level_db.get(KEY_PREFIX[:master]).nil?
      end

    end
  end
end