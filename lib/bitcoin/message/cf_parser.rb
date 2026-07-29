module Bitcoin
  module Message
    module CFParser

      def parse_from_payload(payload)
        type, start, hash = payload.unpack('CVH*')
        self.new(type, start, hash)
      end

      def to_payload
        [filter_type, start_height, stop_hash].pack('CVH*')
      end

    end
  end
end