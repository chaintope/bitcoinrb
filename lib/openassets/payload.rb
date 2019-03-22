# frozen_string_literal: true

module OpenAssets

  MARKER = "\x4f\x41"
  VERSION = "\x01\x00"

  # the open assets payload
  class Payload

    attr_accessor :quantities
    attr_accessor :metadata

    def initialize(quantities = [], metadata = '')
      @quantities = quantities
      @metadata = metadata
    end

    # parse open assets payload
    # @return [Payload] a open assets payload object, if payload is invalid, return nil.
    def self.parse_from_payload(payload)
      buf = StringIO.new(payload)
      marker = buf.read(2)
      version = buf.read(2)
      return nil if marker != MARKER || version != VERSION
      count = Bitcoin.unpack_var_int_from_io(buf)
      return nil unless count
      quantities = []
      count.times do
        quantities << LEB128.decode_unsigned(buf, buf.pos)
      end
      metadata_length = Bitcoin.unpack_var_int_from_io(buf)
      return nil if metadata_length.nil? || buf.length < metadata_length + buf.pos
      metadata = buf.read(metadata_length).each_byte.map(&:chr).join
      new(quantities, metadata)
    rescue
      # LEB128#decode_unsigned raise 'undefined method `unpack' for nil:NilClass'
      # for invalid format such as "018f8f" (the most significant bit of the last byte should be 0)
      nil
    end

    # generate binary payload
    def to_payload
      payload = String.new
      payload << MARKER
      payload << VERSION
      payload << Bitcoin.pack_var_int(quantities.size) << quantities.map{|q| LEB128.encode_unsigned(q).read }.join
      payload << Bitcoin.pack_var_int(metadata.length) << metadata.bytes.map{|b| sprintf("%02x", b)}.join.htb
      payload
    end

  end

end
