module Bitcoin
  module Message

    # cmpctblock message
    # https://github.com/bitcoin/bips/blob/master/bip-0152.mediawiki
    class CmpctBlock < Base

      COMMAND = 'cmpctblock'

      attr_accessor :header_and_short_ids

      def initialize(header_and_short_ids)
        @header_and_short_ids = header_and_short_ids
      end

      def self.parse_from_payload(payload)
        self.new(HeaderAndShortIDs.parse_from_payload(payload))
      end

      def to_payload
        header_and_short_ids.to_payload
      end

    end

  end
end
