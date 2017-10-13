require 'eventmachine'

module Bitcoin
  module Network

    autoload :MessageHandler, 'bitcoin/network/message_handler'
    autoload :Connection, 'bitcoin/network/connection'
    autoload :Pool, 'bitcoin/network/pool'
    autoload :Peer, 'bitcoin/network/peer'
    autoload :PeerDiscovery, 'bitcoin/network/peer_discovery'

  end
end
