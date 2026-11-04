module Bitcoin
  module Wallet

    # the account in BIP-44
    class Account
      include Bitcoin::HexConverter

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
        @name = normalize_name(name)
        @receive_depth = 0
        @change_depth = 0
        @lookahead = 10
        @account_key = account_key
      end

      # Parse an account from the payload made by #to_payload.
      # @param [String] payload
      # @return [Bitcoin::Wallet::Account]
      # @raise [ArgumentError] If the payload is truncated, has data after the account, or holds invalid values.
      def self.parse_from_payload(payload)
        raise ArgumentError, 'payload must be a String.' unless payload.is_a?(String)
        buf = StringIO.new(payload)
        account_key = Bitcoin::ExtPubkey.parse_from_payload(Bitcoin.read_exact(buf, 78))
        name_size = Bitcoin.unpack_var_int_from_io(buf)
        raise ArgumentError, 'Payload is truncated.' if name_size.nil?
        name = Bitcoin.read_exact(buf, name_size).force_encoding('utf-8')
        purpose, index, receive_depth, change_depth, lookahead = Bitcoin.read_exact(buf, 20).unpack('V5')
        raise ArgumentError, 'Account payload has data after the account.' unless buf.eof?
        a = Account.new(account_key, purpose, index, name)
        a.receive_depth = receive_depth
        a.change_depth = change_depth
        a.lookahead = lookahead
        a
      end

      def to_payload
        payload = account_key.to_payload
        payload << Bitcoin.pack_var_string(name.b)
        payload << [purpose, index, receive_depth, change_depth, lookahead].pack('V*')
        payload
      end

      # whether support witness
      def witness?
        [PURPOSE_TYPE[:nested_witness], PURPOSE_TYPE[:native_segwit]].include?(purpose)
      end

      # create new receive key
      # @return [Bitcoin::ExtPubkey]
      def create_receive
        @receive_depth += 1
        save
        save_key(0, @receive_depth, derive_key(0, @receive_depth))
      end

      # create new change key
      # @return [Bitcoin::ExtPubkey]
      def create_change
        @change_depth += 1
        save
        save_key(1, @change_depth, derive_key(1, @change_depth))
      end

      # save this account payload to database.
      def save
        wallet.db.save_account(self)
        save_key(0, receive_depth, derive_key(0, receive_depth)) if receive_depth.zero?
        save_key(1, change_depth, derive_key(1, change_depth)) if change_depth.zero?
      end

      # @param purpose 0:recieve, 1:change
      # @param index receive_depth or change_depth
      # @param key the key to be saved
      def save_key(purpose, index, key)
        wallet.db.save_key(self, purpose, index, key)
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
        wallet.db.get_keys(self).map { |key| Bitcoin.hash160(key) }
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

      # The name is stored as its UTF-8 bytes and read back as UTF-8, so that it has to be valid UTF-8.
      # @raise [ArgumentError] If +name+ is not a String which converts to valid UTF-8.
      def normalize_name(name)
        raise ArgumentError, 'name must be a String.' unless name.is_a?(String)
        utf8 = name.encode(Encoding::UTF_8)
        raise ArgumentError, 'name must be valid UTF-8.' unless utf8.valid_encoding?
        utf8
      rescue EncodingError
        raise ArgumentError, 'name must be valid UTF-8.'
      end

      # @raise [ArgumentError] If a parameter is invalid or they do not match each other.
      def validate_params!(account_key, purpose, index)
        raise ArgumentError, 'account_key must be an instance of Bitcoin::ExtPubkey.' unless account_key.is_a?(Bitcoin::ExtPubkey)
        raise ArgumentError, "purpose must be one of #{PURPOSE_TYPE.values.join(', ')}." unless PURPOSE_TYPE.value?(purpose)
        raise ArgumentError, 'index must be an integer from 0 to 2**31 - 1.' unless index.is_a?(Integer) && index.between?(0, Bitcoin::HARDENED_THRESHOLD - 1)
        raise ArgumentError, 'Account key and index does not match.' unless account_key.number == (index + Bitcoin::HARDENED_THRESHOLD)
        version_bytes = Bitcoin::ExtPubkey.version_from_purpose(purpose + Bitcoin::HARDENED_THRESHOLD)
        raise ArgumentError, 'The purpose and the account key do not match.' unless account_key.version == version_bytes
      end

    end

  end
end
