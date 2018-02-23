require 'leveldb'
module Bitcoin
  module Wallet

    class Base

      attr_accessor :wallet_id
      attr_reader :db
      attr_reader :path

      DEFAULT_PATH_PREFIX = "#{Bitcoin.base_dir}/db/wallet/"
      VERSION = 1

      # Create new wallet. If wallet already exist, throw error.
      # The wallet generates a seed using SecureRandom and store to db at initialization.
      # @param [String] wallet_id new wallet id.
      # @param [String] path_prefix wallet file path prefix.
      # @return [Bitcoin::Wallet::Base] the wallet
      def self.create(wallet_id = 1, path_prefix = DEFAULT_PATH_PREFIX)
        raise ArgumentError, "wallet_id : #{wallet_id} already exist." if self.exist?(wallet_id, path_prefix)
        w = self.new(wallet_id, path_prefix)
        # generate seed
        raise RuntimeError, 'the seed already exist.' if w.db.registered_master?
        master = Bitcoin::Wallet::MasterKey.generate
        w.db.register_master_key(master)
        w.create_account('Default')
        w
      end

      # load wallet with specified +wallet_id+
      # @return [Bitcoin::Wallet::Base] the wallet
      def self.load(wallet_id, path_prefix = DEFAULT_PATH_PREFIX)
        raise ArgumentError, "wallet_id : #{wallet_id} dose not exist." unless self.exist?(wallet_id, path_prefix)
        self.new(wallet_id, path_prefix)
      end

      # get wallets path
      # @return [Array] Array of paths for each wallet dir.
      def self.wallet_paths(path_prefix = DEFAULT_PATH_PREFIX)
        Dir.glob("#{path_prefix}wallet*/").sort
      end

      # get current wallet
      def self.current_wallet(path_prefix = DEFAULT_PATH_PREFIX)
        path = wallet_paths.first # TODO default wallet selection
        return nil unless path
        wallet_id = path.delete(path_prefix + '/wallet').delete('/').to_i
        self.load(wallet_id, path_prefix)
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

      def create_account(purpose = Account::PURPOSE_TYPE[:native_segwit], name)
        accounts = accounts(purpose)
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

    end

  end
end
