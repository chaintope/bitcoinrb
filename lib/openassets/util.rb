# frozen_string_literal: true

module OpenAssets
  module Util
    class << self
      OA_VERSION_BYTE = '17' # 0x23
      OA_VERSION_BYTE_TESTNET = '73' # 0x115

      def script_to_asset_id(script)
        hash_to_asset_id(Bitcoin.hash160(script))
      end

      private

      def hash_to_asset_id(hash)
        hash = oa_version_byte + hash
        Bitcoin::Base58.encode(hash + Bitcoin.calc_checksum(hash))
      end

      def oa_version_byte
        case Bitcoin.chain_params.network
        when 'mainnet' then OA_VERSION_BYTE
        when 'testnet', 'regtest' then OA_VERSION_BYTE_TESTNET
        end
      end
    end
  end
end
