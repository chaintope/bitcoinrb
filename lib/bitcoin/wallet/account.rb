module Bitcoin
  module Wallet

    # the account in BIP-44
    class Account

      PURPOSE_TYPE = {legacy: 44, nested_witness: 49}

      attr_reader :purpose # either 44 or 49
      attr_reader :index # BIP-44 index
      attr_reader :name # account name
      attr_accessor :receive_depth # receive address depth(address index)
      attr_accessor :change_depth # change address depth(address index)
      attr_accessor :lookahead
      attr_accessor :wallet

      def initialize(purpose = PURPOSE_TYPE[:nested_witness], index = 0, name = '')
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
        @receive_depth = lookahead
        @change_depth = lookahead
        @index = wallet.accounts.size
        save
      end

      # derive receive key
      def derive_receive(address_index)
        derive_key(0, address_index)
      end

      # derive change key
      def derive_change(address_index)
        derive_key(1, address_index)
      end

      # save this account payload to database.
      def save
        wallet.db.save_account(self)
      end

      # get the list of derived keys for receive key.
      def derived_receive_keys
        receive_depth.times.map{|i|derive_key(0,i)}
      end

      # get the list of derived keys for change key.
      def derived_change_keys
        receive_depth.times.map{|i|derive_key(1,i)}
      end

      private

      def derive_key(branch, address_index)
        account_key.derive(branch).derive(address_index)
      end

      def account_key
        return @cached_account_key if @cached_account_key
        coin_type = Bitcoin.chain_params.bip44_coin_type
        # m / purpose' / coin_type' / account_index'
        @cached_account_key = wallet.master_key.key.derive(2**31 + purpose).derive(2**31 + coin_type).derive(2**31 + index)
      end

    end

  end
end
