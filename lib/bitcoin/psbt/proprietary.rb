module Bitcoin
  module PSBT
    # Proprietary element of PSBT
    # https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki#Proprietary_Use_Type
    class Proprietary
      attr_accessor :identifier # binary format
      attr_accessor :sub_type # integer
      attr_accessor :value # binary format

      # @param [String] key key with binary format without key type(0xfc).
      # @param [String] value value with binary format.
      def initialize(key, value)
        buf = StringIO.new(key)
        id_len = Bitcoin.unpack_var_int_from_io(buf)
        @identifier = buf.read(id_len)
        @sub_type = Bitcoin.unpack_var_int_from_io(buf)
        @value = value
      end

      # Show contents
      # @return [String]
      def to_s
        "identifier: #{identifier&.bth}, sub type: #{sub_type}, value: #{value&.bth}"
      end

      # Get key data with key type(0xfc).
      # @return [String] key data with binary format.
      def key
        k = [PSBT_GLOBAL_TYPES[:proprietary]].pack('C')
        k << Bitcoin.pack_var_int(identifier ? identifier.bytesize : 0)
        k << identifier if identifier
        k << Bitcoin.pack_var_int(sub_type)
        k
      end

      # Convert to payload
      # @return [String] payload with binary format.
      def to_payload
        k = key
        Bitcoin.pack_var_int(k.bytesize) + k + Bitcoin.pack_var_int(value.bytesize) + value
      end

      def to_h
        {identifier: identifier.bth, sub_type: sub_type, value: value.bth}
      end
    end
  end
end
