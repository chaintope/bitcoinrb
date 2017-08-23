module Bitcoin

  # witness
  class ScriptWitness

    attr_reader :stack

    def initialize(stack = [])
      @stack = stack
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