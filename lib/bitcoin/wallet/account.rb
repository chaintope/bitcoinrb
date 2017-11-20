module Bitcoin
  module Wallet

    # the account in BIP-44
    class Account

      PURPOSE_TYPE = {legacy: 44, nested_witness: 49}

      attr_reader :purpose # either 44 or 49
      attr_reader :index # BIP-44 index
      attr_reader :name # account name
      attr_accessor :receive_depth # receive address depth
      attr_accessor :change_depth # change address depth
      attr_accessor :lookahead
      attr_accessor :wallet

      def initialize(purpose = PURPOSE_TYPE[:legacy], index = 0, name = '')
        @purpose = purpose
        @index = index
        @name = name
        @receive_depth = 0
        @change_depth = 0
        @lookahead = 10
      end

      def self.parse_from_payload(payload)
        name, payload = Bitcoin.unpack_var_string(payload)
        name = name.force_encoding('utf-8')
        purpose, index, receive_depth, change_depth, lookahead = payload.unpack('I*')
        a = Account.new(purpose, index, name)
        a.receive_depth = receive_depth
        a.change_depth = change_depth
        a.lookahead = lookahead
        a
      end

      def to_payload
        payload = Bitcoin.pack_var_string(name.unpack('H*').first.htb)
        payload << [purpose, index, receive_depth, change_depth, lookahead].pack('I*')
        payload
      end

      # whether support witness
      def witness?
        purpose == PURPOSE_TYPE[:nested_witness]
      end

      def init
        lookahead.times do |index|
          derive_receive(index)
          derive_change(index)
        end
        @index = wallet.accounts.size
        save
      end

      # derive receive key
      def derive_receive(index)
        derive(0, index)
      end

      # derive change key
      def derive_change(index)
        derive(1, index)
      end

      # save this account payload to database.
      def save
        wallet.db.save_account(self)
      end

      private

      # derive key
      def derive(branch, index)

      end

    end

  end
end
