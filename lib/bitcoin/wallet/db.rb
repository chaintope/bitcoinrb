module Bitcoin
  module Wallet

    class DB

      KEY_PREFIX = {
          account: 'a',       # key: account index, value: Account raw data.
          master: 'm',        # value: wallet seed.
          version: 'v',       # value: wallet version
          key: 'k',           # key: path to the key, value: public key
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
          id = [account.purpose, account.index].pack('I*').bth
          key = KEY_PREFIX[:account] + id
          level_db.put(key, account.to_payload)
        end
      end

      def save_key(account, purpose, index, key)
        pubkey = key.pub
        id = [account.purpose, account.index, purpose, index].pack('I*').bth
        k = KEY_PREFIX[:key] + id
        level_db.put(k, pubkey)
        key
      end

      def get_keys(account)
        id = [account.purpose, account.index].pack('I*').bth
        from = KEY_PREFIX[:key] + id + '00000000'
        to = KEY_PREFIX[:key] + id + 'ffffffff'
        level_db.each(from: from, to: to).map { |k, v| v}
      end

      def get_keys_type(account, purpose)
        id = [account.purpose, account.index, purpose].pack('I*').bth
        from = KEY_PREFIX[:key] + id + '00000000'
        to = KEY_PREFIX[:key] + id + 'ffffffff'
        level_db.each(from: from, to: to).map { |k, v| v}
      end

      def get_keys_and_addresses(account)
        return [] unless account.purpose == Bitcoin::Wallet::Account::PURPOSE_TYPE[:legacy] or account.purpose == Bitcoin::Wallet::Account::PURPOSE_TYPE[:native_segwit]
        keys = get_keys(account)
        addresses = []
        keys.each do |key|
          case account.purpose 
          when Bitcoin::Wallet::Account::PURPOSE_TYPE[:legacy]
            addresses.push(Bitcoin::Key.new(pubkey: key, key_type: Bitcoin::Key::TYPES[:p2pkh]).to_p2pkh)
          when Bitcoin::Wallet::Account::PURPOSE_TYPE[:nested_witness]
            addresses.push(Bitcoin::Key.new(pubkey: key, key_type: Bitcoin::Key::TYPES[:p2pkh]).to_nested_p2wpkh)
          when Bitcoin::Wallet::Account::PURPOSE_TYPE[:native_segwit]
            addresses.push(Bitcoin::Key.new(pubkey: key, key_type: Bitcoin::Key::TYPES[:p2wpkh]).to_p2wpkh)
          end
        end
        addresses
      end

      # get master_key
      def master_key
        @master_key ||= Bitcoin::Wallet::MasterKey.parse_from_payload(level_db.get(KEY_PREFIX[:master]))
      end

      # save seed
      # @param [Bitcoin::Wallet::MasterKey] master a master key.
      def register_master_key(master)
        level_db.put(KEY_PREFIX[:master], master.to_payload)
        level_db.put(KEY_PREFIX[:version], Bitcoin::Wallet::Base::VERSION.to_s)
        @master_key = master
      end

      # whether master key registered.
      def registered_master?
        !level_db.get(KEY_PREFIX[:master]).nil?
      end

      # wallet version
      def version
        level_db.get(KEY_PREFIX[:version]).to_i
      end

    end
  end
end
