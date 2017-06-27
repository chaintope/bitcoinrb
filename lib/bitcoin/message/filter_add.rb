module Bitcoin
  module Message

    # filteradd message
    # https://bitcoin.org/en/developer-reference#filteradd
    class FilterAdd < Base

      COMMAND = 'filteradd'

      attr_accessor :element

      def initialize(element)
        @element = element
      end

      def self.parse_from_payload(payload)
        new(Bitcoin.unpack_var_string(payload).first.reverse.bth)
      end

      def to_payload
        Bitcoin.pack_var_string(element.htb.reverse)
      end

    end

  end
end
