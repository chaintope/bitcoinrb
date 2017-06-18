module Bitcoin
  module Message

    # inv message
    # https://bitcoin.org/en/developer-reference#inv
    class Inv < Base

      attr_reader :inventories

      def initialize(inventories = [])
        @inventories = inventories
      end

      def self.parse_from_payload(payload)
        size, payload = Bitcoin.unpack_var_int(payload)
        buf = StringIO.new(payload)
        i = new
        size.times do
          i.inventories << Inventory.parse_from_payload(buf.read(36))
        end
        i
      end

      def command
        'inv'
      end

      def to_payload
        Bitcoin.pack_var_int(inventories.length) << inventories.map(&:to_payload).join
      end
    end

  end
end