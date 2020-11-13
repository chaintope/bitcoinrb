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

  class << self
    alias_method :base_decode, :decode
  end

  def self.decode(string, group, allow_hybrid: false)
    string = string.dup.force_encoding('BINARY')
    raise ECDSA::Format::DecodeError, 'Point octet string is empty.' if string.empty?
    if [6, 7].include?(string[0].ord)
      raise ECDSA::Format::DecodeError, 'Unrecognized start byte for point octet string: 0x%x' % string[0].ord unless allow_hybrid
      decode_uncompressed string, group if allow_hybrid
    else
      base_decode(string, group)
    end
  end

end