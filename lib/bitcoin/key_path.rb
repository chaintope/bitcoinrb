module Bitcoin
  module KeyPath

    # key path convert an array of derive number
    # A hardened index is marked with a trailing ' or h, as Bitcoin Core's ParseHDKeypath reads it.
    # @param [String] path_string
    # @return [Array[Integer]] key path numbers.
    # @raise [ArgumentError] if invalid +path_string+.
    def parse_key_path(path_string)
      paths = path_string.split('/')
      raise ArgumentError, "Invalid path." if path_string.include?(" ")
      raise ArgumentError, "Invalid path." unless path_string.count("/") <= paths.size
      paths.map.with_index do|p, index|
        if index == 0
          next if p == 'm'
          raise ArgumentError, "Invalid path." unless p == 'm'
        end
        hardened = p.end_with?("'", 'h')
        number = hardened ? p[0...-1] : p
        raise ArgumentError, "Invalid path." unless number =~ /\A[0-9]+\z/
        value = number.to_i
        # 4294967295 = 0xFFFFFFFF (uint32 max)
        raise ArgumentError, "Invalid path." if value > (hardened ? Bitcoin::HARDENED_THRESHOLD - 1 : 4294967295)
        hardened ? value + Bitcoin::HARDENED_THRESHOLD : value
      end[1..-1]
    end

    # key path numbers convert to path string.
    # @param [Array[Integer]] key path numbers.
    # @return [String] path string.
    def to_key_path(numbers)
      "m/#{numbers.map{|p| p >= Bitcoin::HARDENED_THRESHOLD ? "#{p - Bitcoin::HARDENED_THRESHOLD}'" : p.to_s}.join('/')}"
    end

  end
end