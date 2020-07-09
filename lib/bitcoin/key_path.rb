module Bitcoin
  module KeyPath

    # key path convert an array of derive number
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
        raise ArgumentError, "Invalid path." if p.count("'") > 1 || (p.count("'") == 1 && p[-1] != "'")
        raise ArgumentError, "Invalid path." unless p.delete("'") =~ /^[0-9]+$/
        value = (p[-1] == "'" ? p.delete("'").to_i + Bitcoin::HARDENED_THRESHOLD : p.to_i)
        raise ArgumentError, "Invalid path." if value > 4294967295 # 4294967295 = 0xFFFFFFFF (uint32 max)
        value
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