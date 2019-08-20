module Bitcoin
  module KeyPath

    # key path convert an array of derive number
    # @param [String] path_string
    # @return [Array[Integer]] key path numbers.
    def parse_key_path(path_string)
      path_string.split('/').map.with_index do|p, index|
        if index == 0
          raise ArgumentError.new("#{path_string} is invalid format.") unless p == 'm'
          next
        end
        raise ArgumentError.new("#{path_string} is invalid format.") unless p.delete("'") =~ /^[0-9]+$/
        (p[-1] == "'" ? p.delete("'").to_i + Bitcoin::HARDENED_THRESHOLD : p.to_i)
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