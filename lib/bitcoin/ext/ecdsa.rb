class ::ECDSA::Signature
  # convert signature to der string.
  def to_der
    ECDSA::Format::SignatureDerString.encode(self)
  end
end

class ::ECDSA::Point
  def to_hex(compression = true)
    ECDSA::Format::PointOctetString.encode(self, compression: compression).bth
  end
end

module ::ECDSA::Format::PointOctetString

  def self.decode(string, group, allow_hybrid: false)
    string = string.dup.force_encoding('BINARY')

    raise ECDSA::Format::DecodeError, 'Point octet string is empty.' if string.empty?

    case string[0].ord
    when 0
      check_length string, 1
      return group.infinity
    when 2
      decode_compressed string, group, 0
    when 3
      decode_compressed string, group, 1
    when 4
      decode_uncompressed string, group
    when 6..7
      raise DecodeError, 'Unrecognized start byte for point octet string: 0x%x' % string[0].ord unless allow_hybrid
      decode_uncompressed string, group if allow_hybrid
    else
      raise ECDSA::Format::DecodeError, 'Unrecognized start byte for point octet string: 0x%x' % string[0].ord
    end
  end

end