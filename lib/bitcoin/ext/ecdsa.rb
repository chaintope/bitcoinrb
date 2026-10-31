class ::ECDSA::Signature
  # convert signature to der string.
  def to_der
    ECDSA::Format::SignatureDerString.encode(self)
  end

  def ==(other)
    return false unless other.is_a?(ECDSA::Signature)
    r == other.r && s == other.s
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
      point = decode_uncompressed(string, group)
      # A hybrid encoding carries the parity of y in its first byte, 0x06 for even and 0x07 for odd, and
      # libsecp256k1 rejects the point when the byte does not match the y it carries.
      unless point.infinity? || (string[0].ord == 6) == point.y.even?
        raise ECDSA::Format::DecodeError, 'Hybrid point octet string has a parity byte which does not match y.'
      end
      point
    else
      base_decode(string, group)
    end
  end

end