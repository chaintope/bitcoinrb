module Bitcoin
  module Message

    # P2P message layer Error
    # It is an ArgumentError, like the errors the other parsers raise, so that every failure to parse
    # data from a peer can be rescued as one.
    class Error < ArgumentError

    end

  end
end