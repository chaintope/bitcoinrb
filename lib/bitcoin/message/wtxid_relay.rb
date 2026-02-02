module Bitcoin
  module Message
    # wtxidrelay message for BIP-339
    # https://github.com/bitcoin/bips/blob/master/bip-0339.mediawiki
    class WTXIDRelay < Base

      COMMAND = 'wtxidrelay'

      def to_payload
        ''
      end
    end
  end
end