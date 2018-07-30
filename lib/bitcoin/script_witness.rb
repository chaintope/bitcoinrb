module Bitcoin

  # witness
  class ScriptWitness

    attr_reader :stack

    def initialize(stack = [])
      @stack = stack
    end

    def self.parse_from_payload(payload)
      buf = payload.is_a?(StringIO) ? payload : StringIO.new(payload)
      size = Bitcoin.unpack_var_int_from_io(buf)
      stack = size.times.map do
        buf.read(Bitcoin.unpack_var_int_from_io(buf))
      end
      self.new(stack)
    end

    def empty?
      stack.empty?
    end

    def to_payload
      p = Bitcoin.pack_var_int(stack.size)
      p << stack.map { |s|
        Bitcoin.pack_var_int(s.bytesize) << s
      }.join
    end

    def to_s
      stack.map{|s|s.bth}.join(' ')
    end

  end

end