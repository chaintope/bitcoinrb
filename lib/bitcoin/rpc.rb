module Bitcoin
  module RPC
    autoload :HttpServer, 'bitcoin/rpc/http_server'
    autoload :RequestHandler, 'bitcoin/rpc/request_handler'
    autoload :BitcoinCoreClient, 'bitcoin/rpc/bitcoin_core_client'
  end
end
