require 'leveldb'
module Bitcoin
  module Wallet

    class Base

      attr_reader :db

      def initialize(path = "#{Bitcoin.base_dir}/db/wallet")
        @db = Bitcoin::Wallet::DB.new(path)
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

    end

  end
end
