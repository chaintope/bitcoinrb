module Bitcoin
  module Message
    module CFParser

      def parse_from_payload(payload)
        raise Bitcoin::Message::Error, 'Payload must be 37 bytes.' unless payload.bytesize == 37
        type, start, hash = payload.unpack('CVH*')
        self.new(type, start, hash)
      end

      def to_payload
        [filter_type, start_height, stop_hash].pack('CVH*')
      end

    end
  end
end