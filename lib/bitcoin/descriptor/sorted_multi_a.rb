module Bitcoin
  module Descriptor
    # sortedmulti_a expression
    # @see https://github.com/bitcoin/bips/blob/master/bip-0387.mediawiki
    class SortedMultiA < MultiA
      def type
        :sortedmulti_a
      end

      def to_script
        multisig_script( keys.map{|k| extract_pubkey(k).xonly_pubkey}.sort)
      end
    end
  end
end