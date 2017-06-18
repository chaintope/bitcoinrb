module Bitcoin
  module Message

    # notfound message
    # https://bitcoin.org/en/developer-reference#notfound
    class NotFound < Base

      attr_accessor :inventory

      def initialize(identifier, hash)
        @inventory = Inventory.new(identifier, hash)
      end

      def self.parse_from_payload(payload)
        size, inventory_payload = Bitcoin.unpack_var_int(payload)
        inventory = Inventory.parse_from_payload(inventory_payload)
        new(inventory.identifier, inventory.hash)
      end

      def command
        'notfound'
      end

      def to_payload
        Bitcoin.pack_var_int(1) << inventory.to_payload
      end

    end
  end

end
