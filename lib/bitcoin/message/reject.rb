module Bitcoin
  module Message

    # reject message
    # https://bitcoin.org/en/developer-reference#reject
    class Reject < Base

      attr_accessor :message
      attr_accessor :code
      attr_accessor :reason
      attr_accessor :extra

      COMMAND = 'reject'

      CODE_MALFORMED = 0x01
      CODE_INVALID = 0x10
      CODE_OBSOLETE = 0x11
      CODE_DUPLICATE = 0x12
      CODE_NONSTANDARD = 0x40
      CODE_DUST = 0x41
      CODE_INSUFFICIENT_FEE = 0x42
      CODE_CHECKPOINT = 0x43

      def initialize(message, code, reason = '', extra = '')
        @message = message
        @code = code
        @reason = reason
        @extra = extra
      end

      def self.parse_from_payload(payload)
        message, payload = Bitcoin.unpack_var_string(payload)
        code, payload = payload.unpack('Ca*')
        reason, payload = Bitcoin.unpack_var_string(payload)
        extra = ['tx', 'block'].include?(message) ? payload.bth : payload
        new(message, code, reason, extra)
      end

      def to_payload
        e = ['tx', 'block'].include?(message) ? extra.htb : extra
        Bitcoin.pack_var_string(message) << [code].pack('C') << Bitcoin.pack_var_string(reason) << e
      end

    end
  end
end
