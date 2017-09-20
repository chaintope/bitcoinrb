require 'parallel'
require 'eventmachine'

module Bitcoin
  module Network

    autoload :Connection, 'bitcoin/network/connection'
    autoload :Pool, 'bitcoin/network/pool'
    autoload :Peer, 'bitcoin/network/peer'
    autoload :PeerDiscovery, 'bitcoin/network/peer_discovery'

  end
end
