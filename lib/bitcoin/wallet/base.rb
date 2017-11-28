require 'leveldb'
module Bitcoin
  module Wallet

    class Base

      attr_accessor :wallet_id
      attr_reader :db

      DEFAULT_PATH_PREFIX = "#{Bitcoin.base_dir}/db/wallet"

      # create new wallet. if
      # @param [String] wallet_id new wallet id.
      # @param [String] path_prefix wallet file path prefix.
      # @return [Bitcoin::Wallet::Base] wallet object.
      def self.create(wallet_id = 1, path_prefix = DEFAULT_PATH_PREFIX)
        raise ArgumentError, "wallet_id : #{wallet_id} already exist." if self.exist?(wallet_id, path_prefix)
        w = self.new(wallet_id, path_prefix)
        w.init
        w
      end

      # load wallet with specified +wallet_id+
      def self.load(wallet_id, path_prefix = DEFAULT_PATH_PREFIX)
        raise ArgumentError, "wallet_id : #{wallet_id} dose not exist." unless self.exist?(wallet_id, path_prefix)
        self.new(wallet_id, path_prefix)
      end

      # get account list based on BIP-44
      def accounts
        db.accounts.map{|raw| Account.parse_from_payload(raw)}
      end

      def create_account(purpose = Account::PURPOSE_TYPE[:legacy], index = 0, name)
        account = Account.new(purpose, index, name)
        account.wallet = self
        account.init
        account
      end

      # close database wallet
      def close
        db.close
      end

      # initialize wallet
      def init
        raise RuntimeError, 'the seed already exist.' if db.seed
        seed = SecureRandom.hex(16)
        db.register_seed(seed)
      end

      private

      def initialize(wallet_id, path_prefix)
        @db = Bitcoin::Wallet::DB.new("#{path_prefix}_#{wallet_id}")
        @wallet_id = wallet_id
      end

      def self.exist?(wallet_id, path_prefix)
        path = "#{path_prefix}_#{wallet_id}"
        Dir.exist?(path)
      end

    end

  end
end
