module Bitcoin
  module Message

    autoload :Handler, 'bitcoin/message/handler'
    autoload :Base, 'bitcoin/message/base'
    autoload :Version, 'bitcoin/message/version'
    autoload :Verack, 'bitcoin/message/verack'
    autoload :Ping, 'bitcoin/message/ping'
    autoload :Pong, 'bitcoin/message/pong'
    autoload :Error, 'bitcoin/message/error'

    HEADER_SIZE = 24
    USER_AGENT = "/bitcoinrb:#{Bitcoin::VERSION}/"

  end
end