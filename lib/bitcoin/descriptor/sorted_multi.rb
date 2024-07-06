module Bitcoin
  module Descriptor
    # sortedmulti() expression
    class SortedMulti < Multi

      def type
        :sortedmulti
      end

      def to_script
        Script.to_multisig_script(threshold, keys.map{|key| extract_pubkey(key).pubkey }, sort: true)
      end
    end
  end
end