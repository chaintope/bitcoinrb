require 'leveldb-native'
module Bitcoin
  module Wallet

    class Base

      attr_accessor :wallet_id
      attr_reader :db
      attr_reader :path

      VERSION = 1

      # A wallet id names the directory +wallet<id>+ under the path prefix, so that it may hold only
      # letters, digits, '_' and '-'. A '/' or '..' would put the wallet outside the prefix.
      WALLET_ID_PATTERN = /\A[A-Za-z0-9_-]+\z/

      # get wallet dir path
      def self.default_path_prefix
        "#{Bitcoin.base_dir}/db/wallet/"
      end

      # Create new wallet. If wallet already exist, throw error.
      # The wallet generates a seed using SecureRandom and store to db at initialization.
      # @param [Integer, String] wallet_id new wallet id, which consists of letters, digits, '_' and '-'.
      # @param [String] path_prefix wallet file path prefix.
      # @return [Bitcoin::Wallet::Base] the wallet
      # @raise [ArgumentError] If +wallet_id+ is invalid or the wallet already exists.
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
      # @raise [ArgumentError] If +wallet_id+ is invalid or the wallet does not exist.
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
      # @return [Bitcoin::Wallet::Base] the wallet of the first wallet dir, or nil if there is none.
      # Its wallet_id is an Integer if it consists of digits only, otherwise a String.
      def self.current_wallet(path_prefix = default_path_prefix)
        # TODO default wallet selection
        ids = wallet_paths(path_prefix).map { |path| File.basename(path).delete_prefix('wallet') }
        id = ids.find { |i| i.match?(WALLET_ID_PATTERN) } # A dir such as "wallet/" has no wallet id.
        return nil unless id
        self.load(id.match?(/\A[0-9]+\z/) ? id.to_i : id, path_prefix)
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
      # @param [String] name a account name, which has to be unique in the wallet whatever the purpose.
      # @return [Bitcoin::Wallet::Account]
      # @raise [ArgumentError] If an account with +name+ already exists.
      def create_account(purpose = Account::PURPOSE_TYPE[:native_segwit], name)
        # An account is looked up by its name alone, e.g. in #generate_new_address.
        raise ArgumentError.new('Account already exists.') if find_account(name)
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
      # @return [Integer] the balance in satoshis.
      def get_balance(account)
        # TODO get from utxo db.
        0
      end

      # create new bitcoin address for receiving payments.
      # @param [String] account_name an account name.
      # @param [Integer] purpose BIP44's purpose of the account, which is required only when a wallet
      # created by an older version has accounts of the same name with different purposes.
      # @return [String] generated address.
      # @raise [ArgumentError] If no account, or more than one account, matches.
      def generate_new_address(account_name, purpose = nil)
        candidates = accounts(purpose).select{|a| a.name == account_name}
        raise ArgumentError.new('Account does not exist.') if candidates.empty?
        raise ArgumentError.new('More than one account has the name, specify the purpose.') if candidates.size > 1
        candidates.first.create_receive.addr
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

      # decrypt wallet, and store its seed unencrypted.
      # @param [String] passphrase the wallet passphrase
      # @raise [ArgumentError] If +passphrase+ is wrong.
      def decrypt(passphrase)
        master_key.decrypt(passphrase)
        db.register_master_key(master_key)
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
        self.class.validate_wallet_id!(wallet_id)
        @path = "#{path_prefix}wallet#{wallet_id}/"
        @db = Bitcoin::Wallet::DB.new(@path)
        @wallet_id = wallet_id
      end

      def self.exist?(wallet_id, path_prefix)
        validate_wallet_id!(wallet_id)
        path = "#{path_prefix}wallet#{wallet_id}"
        Dir.exist?(path)
      end

      def self.validate_wallet_id!(wallet_id)
        valid = (wallet_id.is_a?(Integer) && wallet_id >= 0) ||
          (wallet_id.is_a?(String) && wallet_id.match?(WALLET_ID_PATTERN))
        raise ArgumentError, "wallet_id must be a non-negative integer or a string of letters, digits, '_' and '-'." unless valid
      end

      # find account using +account_name+
      def find_account(account_name, purpose = nil)
        accounts(purpose).find{|a| a.name == account_name}
      end

    end

  end
end
