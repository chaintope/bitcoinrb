module Bitcoin
  module Message

    autoload :Handler, 'bitcoin/message/handler'
    autoload :Version, 'bitcoin/message/version'
    autoload :Error, 'bitcoin/message/error'

    HEADER_SIZE = 24
    USER_AGENT = "/bitcoinrb:#{Bitcoin::VERSION}/"

  end
end