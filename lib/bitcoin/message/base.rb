module Bitcoin
  module Message

    # Base message class
    class Base
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

      def to_json
        to_h.to_json
      end

      def to_h
        instance_variables.inject({}) do |result, var|
          key = var.to_s
          key.slice!(0) if key.start_with?('@')
          result.update(key => instance_variable_get(var))
        end
      end

    end

  end
end
