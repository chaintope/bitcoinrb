require 'leveldb-native'
module Bitcoin
  module Wallet

    class Base

      attr_accessor :wallet_id
      attr_reader :db
      attr_reader :path

      VERSION = 1

      # get wallet dir path
      def self.default_path_prefix
        "#{Bitcoin.base_dir}/db/wallet/"
      end

      # Create new wallet. If wallet already exist, throw error.
      # The wallet generates a seed using SecureRandom and store to db at initialization.
      # @param [String] wallet_id new wallet id.
      # @param [String] path_prefix wallet file path prefix.
      # @return [Bitcoin::Wallet::Base] the wallet
      def self.create(wallet_id = 1, path_prefix = default_path_prefix, purpose = Account::PURPOSE_TYPE[:native_segwit])
        raise ArgumentError, "wallet_id : #{wallet_id} already exist." if self.exist?(wallet_id, path_prefix)
        w = self.new(wallet_id, path_prefix)
        # generate seed
        raise RuntimeError, 'the seed already exist.' if w.db.registered_master?
        master = Bitcoin::Wallet::MasterKey.generate
        w.db.register_master_key(master)
        w.create_account(purpose, 'Default')
        w
      end

      # load wallet with specified +wallet_id+
      # @return [Bitcoin::Wallet::Base] the wallet
      def self.load(wallet_id, path_prefix = default_path_prefix)
        raise ArgumentError, "wallet_id : #{wallet_id} dose not exist." unless self.exist?(wallet_id, path_prefix)
        self.new(wallet_id, path_prefix)
      end

      # get wallets path
      # @return [Array] Array of paths for each wallet dir.
      def self.wallet_paths(path_prefix = default_path_prefix)
        Dir.glob("#{path_prefix}wallet*/").sort
      end

      # get current wallet
      def self.current_wallet(path_prefix = default_path_prefix)
        path = wallet_paths(path_prefix).first # TODO default wallet selection
        return nil unless path
        path.slice!(path_prefix + 'wallet')
        path.slice!('/')
        self.load(path.to_i, path_prefix)
      end

      # get account list based on BIP-44
      def accounts(purpose = nil)
        list = []
        db.accounts.each do |raw|
          a = Account.parse_from_payload(raw)
          next if purpose && purpose != a.purpose
          a.wallet = self
          list << a
        end
        list
      end

      # create new account
      # @param [Integer] purpose BIP44's purpose.
      # @param [String] name a account name.
      # @return [Bitcoin::Wallet::Account]
      def create_account(purpose = Account::PURPOSE_TYPE[:native_segwit], name)
        raise ArgumentError.new('Account already exists.') if find_account(name, purpose)
        index = accounts.size
        path = "m/#{purpose}'/#{Bitcoin.chain_params.bip44_coin_type}'/#{index}'"
        account_key = master_key.derive(path).ext_pubkey
        account = Account.new(account_key, purpose, index, name)
        account.wallet = self
        account.save
        account
      end

      # get wallet balance.
      # @param [Bitcoin::Wallet::Account] account a account in the wallet.
      def get_balance(account)
        # TODO get from utxo db.
        0.00000000
      end

      # create new bitcoin address for receiving payments.
      # @param [String] account_name an account name.
      # @return [String] generated address.
      def generate_new_address(account_name)
        account = find_account(account_name)
        raise ArgumentError.new('Account does not exist.') unless account
        account.create_receive.addr
      end

      # get wallet version.
      def version
        db.version
      end

      # close database wallet
      def close
        db.close
      end

      # get master key
      # @return [Bitcoin::Wallet::MasterKey]
      def master_key
        db.master_key
      end

      # encrypt wallet
      # @param [String] passphrase the wallet passphrase
      def encrypt(passphrase)
        master_key.encrypt(passphrase)
        db.register_master_key(master_key)
      end

      # decrypt wallet
      # @param [String] passphrase the wallet passphrase
      def decrypt(passphrase)

      end

      # wallet information
      def to_h
        a = accounts.map(&:to_h)
        { wallet_id: wallet_id, version: version, account_depth: a.size, accounts: a, master: {encrypted: master_key.encrypted} }
      end

      # get data elements tobe monitored with Bloom Filter.
      # @return [Array[String]]
      def watch_targets
        accounts.map(&:watch_targets).flatten
      end

      private

      def initialize(wallet_id, path_prefix)
        @path = "#{path_prefix}wallet#{wallet_id}/"
        @db = Bitcoin::Wallet::DB.new(@path)
        @wallet_id = wallet_id
      end

      def self.exist?(wallet_id, path_prefix)
        path = "#{path_prefix}wallet#{wallet_id}"
        Dir.exist?(path)
      end

      # find account using +account_name+
      def find_account(account_name, purpose = nil)
        accounts(purpose).find{|a| a.name == account_name}
      end

    end

  end
end
