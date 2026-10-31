module Bitcoin
  module Message

    # Common message parser which only handle multiple inventory as payload.
    module InventoriesParser

      def parse_from_payload(payload)
        size, payload = Bitcoin.unpack_var_int(payload)
        raise Bitcoin::Message::Error, "#{self::COMMAND} message size #{size} exceeds #{MAX_INV_SZ}." if size > MAX_INV_SZ
        buf = StringIO.new(payload)
        i = new
        size.times do
          i.inventories << Inventory.parse_from_payload(Bitcoin.read_exact(buf, 36))
        end
        i
      end

      def to_payload
        Bitcoin.pack_var_int(inventories.length) << inventories.map(&:to_payload).join
      end

    end
  end
end