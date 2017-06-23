module Bitcoin

  # witness
  class ScriptWitness

    attr_reader :stack

    def initialize
      @stack = []
    end

    def empty?
      stack.empty?
    end

    def to_payload
      p = Bitcoin.pack_var_int(stack.size)
      p << stack.map { |s|
        b = s.htb
        Bitcoin.pack_var_int(b.bytesize) << b
      }.join
    end

  end

end