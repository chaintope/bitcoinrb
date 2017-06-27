module Bitcoin
  module Message

    # filteradd message
    # https://bitcoin.org/en/developer-reference#filteradd
    class FilterAdd < Base

      COMMAND = 'filteradd'

      # element must be sent in the byte order they would use when appearing in a raw transaction;
      attr_accessor :element

      def initialize(element)
        @element = element
      end

      def self.parse_from_payload(payload)
        new(Bitcoin.unpack_var_string(payload).first.bth)
      end

      def to_payload
        Bitcoin.pack_var_string(element.htb)
      end

    end

  end
end
