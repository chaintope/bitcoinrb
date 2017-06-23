module Bitcoin

  # bitcoin script
  class Script

    attr_accessor :payload

    def initialize(payload)
      @payload = payload
    end

  end

end
