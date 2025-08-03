module Bitcoin
  module Descriptor

    # musig() descriptor class.
    # @see https://github.com/bitcoin/bips/blob/master/bip-0390.mediawiki
    class MuSig < Expression

      # SHA256 of `MuSig2MuSig2MuSig2`
      # https://github.com/bitcoin/bips/blob/master/bip-0328.mediawiki
      CHAINCODE = '868087ca02a6f974c4598924c36b57762d32cb45717167e300622c7167e38965'.htb

      attr_reader :keys
      attr_reader :path

      # Constructor.
      # @param [Array] keys An array of key strings.
      # @param [String] path (Optional) derivation path.
      # @return [Bitcoin::Descriptor::MuSig]
      def initialize(keys, path = nil)
        raise ArgumentError, "keys must be an array." unless keys.is_a?(Array)
        unless path.nil?
          raise ArgumentError, "path must be String." unless path.is_a?(String)
          raise ArgumentError, "path must be start with /." unless path.start_with?("/")
        end
        validate_keys!(keys, path)
        @keys = keys
        @path = path
      end

      def type
        :musig
      end

      def top_level?
        false
      end

      # Convert to single key with hex format.
      # @return [String]
      def to_hex
        sorted_key = Schnorr::MuSig2.sort_pubkeys(keys.map{|k| extract_pubkey(k).pubkey})
        agg_key = Schnorr::MuSig2.aggregate(sorted_key)
        if path.nil?
          agg_key.x_only_pubkey
        else
          ext_key = Bitcoin::ExtPubkey.new
          ext_key.pubkey = agg_key.q.to_hex
          ext_key.depth = 0
          ext_key.chain_code = CHAINCODE
          _, *paths = path.split('/')
          derived_key = derive_path(ext_key, paths)
          derived_key.key.xonly_pubkey
        end
      end

      def to_s(checksum: nil)
        desc = "#{type.to_s}(#{keys.join(',')})"
        desc << path if path
        checksum ? Checksum.descsum_create(desc) : desc
      end

      private

      def validate_keys!(keys, path)
        raise ArgumentError, 'musig() cannot have hardened child derivation.' if path && path.include?('h')
        keys.each do |k|
          if path
            raise ArgumentError, 'Ranged musig() requires all participants to be xpubs.' unless k.start_with?('xpub')
          end
          extract_pubkey(k)
        end
      end
    end
  end
end