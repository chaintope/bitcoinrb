# Porting part of the code from bitcoin-ruby. see the license.
# https://github.com/lian/bitcoin-ruby/blob/master/COPYING

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

    # @return an integer for a valid payload, otherwise nil
    def unpack_var_int(payload)
      case payload.unpack1('C')
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

    # @return an integer for a valid payload, otherwise nil
    def unpack_var_int_from_io(buf)
      uchar = buf.read(1)&.unpack1('C')
      case uchar
      when 0xfd
        buf.read(2)&.unpack1('v')
      when 0xfe
        buf.read(4)&.unpack1('V')
      when 0xff
        buf.read(8)&.unpack1('Q')
      else
        uchar
      end
    end

    def pack_boolean(b)
      b ? [0x01].pack('C') : [0x00].pack('C')
    end

    def unpack_boolean(payload)
      data, payload = payload.unpack('Ca*')
      [(data.zero? ? false : true), payload]
    end

    def sha256(payload)
      Digest::SHA256.digest(payload)
    end

    def double_sha256(payload)
      sha256(sha256(payload))
    end

    # byte convert to the sequence of bits packed eight in a byte with the least significant bit first.
    def byte_to_bit(byte)
      byte.unpack1('b*')
    end

    # padding zero to the left of binary string until bytesize.
    # @param [String] binary string
    # @param [Integer] bytesize total bytesize.
    # @return [String] padded binary string.
    def padding_zero(binary, bytesize)
      return binary unless binary.bytesize < bytesize
      ('00' * (bytesize - binary.bytesize)).htb + binary
    end

    # generate sha256-ripemd160 hash for value
    def hash160(hex)
      Digest::RMD160.hexdigest(Digest::SHA256.digest(hex.htb))
    end

    # Generate tagged hash value.
    # @param [String] tag tag value.
    # @param [String] msg the message to be hashed.
    # @return [String] the hash value with binary format.
    def tagged_hash(tag, msg)
      tag_hash = Digest::SHA256.digest(tag)
      Digest::SHA256.digest(tag_hash + tag_hash + msg)
    end

    # encode Base58 check address.
    # @param [String] hex the address payload.
    # @param [String] addr_version the address version for P2PKH and P2SH.
    # @return [String] Base58 check encoding address.
    def encode_base58_address(hex, addr_version)
      base = addr_version + hex
      Base58.encode(base + calc_checksum(base))
    end

    # decode Base58 check encoding address.
    # @param [String] addr address.
    # @return [Array] hex and address version
    def decode_base58_address(addr)
      hex = Base58.decode(addr)
      if hex.size == 50 && calc_checksum(hex[0...-8]) == hex[-8..-1]
        raise 'Invalid version bytes.' unless [Bitcoin.chain_params.address_version, Bitcoin.chain_params.p2sh_version].include?(hex[0..1])
        [hex[2...-8], hex[0..1]]
      else
        raise 'Invalid address.'
      end
    end

    def calc_checksum(hex)
      double_sha256(hex.htb).bth[0..7]
    end

    DIGEST_NAME_SHA256 = 'sha256'

    def hmac_sha256(key, data)
      OpenSSL::HMAC.digest(DIGEST_NAME_SHA256, key, data)
    end

    # check whether +addr+ is valid address.
    # @param [String] addr an address
    # @return [Boolean] if valid address return true, otherwise false.
    def valid_address?(addr)
      begin
        Bitcoin::Script.parse_from_addr(addr)
        true
      rescue Exception
        false
      end
    end

  end

  module HexConverter

    def to_hex
      to_payload.bth
    end

  end
end
