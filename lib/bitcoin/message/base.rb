module Bitcoin
  module Message

    # Base message class
    class Base
      include Bitcoin::HexConverter
      include Bitcoin::Util
      extend Bitcoin::Util

      # generate message header (binary format)
      # https://bitcoin.org/en/developer-reference#message-headers
      def to_pkt
        payload = to_payload
        magic = Bitcoin.chain_params.magic_head.htb
        command_name = self.class.const_get(:COMMAND, false).ljust(12, "\x00")
        payload_size = [payload.bytesize].pack('V')
        checksum = Bitcoin.double_sha256(payload)[0...4]
        magic << command_name << payload_size << checksum << payload
      end

      # abstract method
      def to_payload
        raise 'to_payload must be implemented in a child class.'
      end

      # Decode message data to message object.
      # @param [String] message with binary format.
      # @return [Bitcoin::Message::XXX] An instance of a class that inherits Bitcoin::Message::Base
      # @raise [ArgumentError] Occurs for data that cannot be decoded.
      def self.from_pkt(message)
        buf = StringIO.new(message)
        magic = buf.read(4)
        raise ArgumentError, 'Invalid magic.' unless magic == Bitcoin.chain_params.magic_head.htb
        command = buf.read(12).delete("\x00")
        length = buf.read(4).unpack1('V')
        checksum = buf.read(4)
        payload = buf.read(length)
        raise ArgumentError, 'Checksum do not match.' unless checksum == Bitcoin.double_sha256(payload)[0...4]
        Bitcoin::Message.decode(command, payload&.bth)
      end

    end

  end
end
