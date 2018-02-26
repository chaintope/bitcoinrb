module Bitcoin
  module Wallet

    # the account in BIP-44
    class Account

      PURPOSE_TYPE = {legacy: 44, nested_witness: 49, native_segwit: 84}

      attr_reader :purpose # either 44 or 49 or 84
      attr_reader :index # BIP-44 index
      attr_reader :name # account name
      attr_reader :account_key # account xpub key Bitcoin::ExtPubkey
      attr_accessor :receive_depth # receive address depth(address index)
      attr_accessor :change_depth # change address depth(address index)
      attr_accessor :lookahead
      attr_accessor :wallet

      def initialize(account_key, purpose = PURPOSE_TYPE[:native_segwit], index = 0, name = '')
        validate_params!(account_key, purpose, index)
        @purpose = purpose
        @index = index
        @name = name
        @receive_depth = 0
        @change_depth = 0
        @lookahead = 10
        @account_key = account_key
      end

      def self.parse_from_payload(payload)
        buf = StringIO.new(payload)
        account_key = Bitcoin::ExtPubkey.parse_from_payload(buf.read(78))
        payload = buf.read
        name, payload = Bitcoin.unpack_var_string(payload)
        name = name.force_encoding('utf-8')
        purpose, index, receive_depth, change_depth, lookahead = payload.unpack('I*')
        a = Account.new(account_key, purpose, index, name)
        a.receive_depth = receive_depth
        a.change_depth = change_depth
        a.lookahead = lookahead
        a
      end

      def to_payload
        payload = account_key.to_payload
        payload << Bitcoin.pack_var_string(name.unpack('H*').first.htb)
        payload << [purpose, index, receive_depth, change_depth, lookahead].pack('I*')
        payload
      end

      # whether support witness
      def witness?
        [PURPOSE_TYPE[:nested_witness], PURPOSE_TYPE[:native_segwit]].include?(purpose)
      end

      # create new receive key
      # @return [Bitcoin::ExtKey]
      def create_receive
        @receive_depth += 1
        save
        derive_key(0, @receive_depth)
      end

      # create new change key
      # # @return [Bitcoin::ExtKey]
      def create_change
        @change_depth += 1
        save
        derive_key(1, @change_depth)
      end

      # save this account payload to database.
      def save
        wallet.db.save_account(self)
      end

      # get the list of derived keys for receive key.
      # @return [Array[Bitcoin::ExtPubkey]]
      def derived_receive_keys
        (receive_depth + 1).times.map{|i|derive_key(0,i)}
      end

      # get the list of derived keys for change key.
      # @return [Array[Bitcoin::ExtPubkey]]
      def derived_change_keys
        (change_depth + 1).times.map{|i|derive_key(1,i)}
      end

      # get account type label.
      def type
        case purpose
          when PURPOSE_TYPE[:legacy]
            'pubkeyhash'
          when PURPOSE_TYPE[:nested_witness]
            'p2wpkh-p2sh'
          when PURPOSE_TYPE[:native_segwit]
            'p2wpkh'
          else
            'unknown'
        end
      end

      # account derivation path
      def path
        "m/#{purpose}'/#{Bitcoin.chain_params.bip44_coin_type}'/#{index}'"
      end

      def watch_only
        false # TODO implements import watch only address.
      end

      # get data elements tobe monitored with Bloom Filter.
      # @return [Array[String]]
      def watch_targets
        derived_receive_keys.map(&:hash160) + derived_change_keys.map(&:hash160)
      end

      def to_h
        {
            name: name, type: type, index: index, receive_depth: receive_depth, change_depth: change_depth,
            look_ahead: lookahead, receive_address: derive_key(0, receive_depth).addr,
            change_address: derive_key(1, change_depth).addr,
            account_key: account_key.to_base58, path: path, watch_only: watch_only
        }
      end

      private

      def derive_key(branch, address_index)
        account_key.derive(branch).derive(address_index)
      end

      def validate_params!(account_key, purpose, index)
        raise 'account_key must be an instance of Bitcoin::ExtPubkey.' unless account_key.is_a?(Bitcoin::ExtPubkey)
        raise 'Account key and index does not match.' unless account_key.number == (index + 2**31)
        version_bytes = Bitcoin::ExtPubkey.version_from_purpose(purpose + 2**31)
        raise 'The purpose and the account key do not match.' unless account_key.version == version_bytes
      end

    end

  end
end
