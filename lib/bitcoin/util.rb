module Bitcoin

  # bitcoin utility.
  # following methods can be used as follows.
  #     Bitcoin.pack_var_int(5)
  module Util

    def pack_var_string(payload)
      pack_var_int(payload.bytesize) + payload
    end

    def unpack_var_string(payload)
      size, payload = unpack_var_int(payload)
      size > 0 ? payload.unpack("a#{size}a*") : [nil, payload]
    end

    def pack_var_int(i)
      if i <  0xfd
        [i].pack('C')
      elsif i <= 0xffff
        [0xfd, i].pack('Cv')
      elsif i <= 0xffffffff
        [0xfe, i].pack('CV')
      elsif i <= 0xffffffffffffffff
        [0xff, i].pack('CQ')
      else
        raise "int(#{i}) too large!"
      end
    end

    def unpack_var_int(payload)
      case payload.unpack('C').first
      when 0xfd
        payload.unpack('xva*')
      when 0xfe
        payload.unpack('xVa*')
      when 0xff
        payload.unpack('xQa*')
      else
        payload.unpack('Ca*')
      end
    end

    def pack_boolean(b)
      b ? [0xFF].pack('C') : [0x00].pack('C')
    end

    def unpack_boolean(payload)
      data, payload = payload.unpack('Ca*')
      [(data.zero? ? false : true), payload]
    end

  end

end
