module Bitcoin
  module Network

    class PeerDiscovery

      attr_reader :logger, :configuration

      def initialize(configuration)
        @logger = Bitcoin::Logger.create(:debug)
        @configuration = configuration
      end

      # get peer addresses, from DNS seeds.
      def peers
        # TODO add find from previous connected peer at first.
        (find_from_dns_seeds + seeds).uniq
      end

      private

      def dns_seeds
        Bitcoin.chain_params.dns_seeds || []
      end

      def seeds
        [*configuration.conf[:connect]]
      end

      def find_from_dns_seeds
        logger.debug 'discover peer address from DNS seeds.'
        dns_seeds.map { |seed|
          begin
            Socket.getaddrinfo(seed, Bitcoin.chain_params.default_port).map{|a|a[2]}.uniq
          rescue SocketError => e
            logger.error "SocketError occurred when load DNS seed: #{seed}, error: #{e.message}"
            nil
          end
        }.flatten.compact
      end
    end
  end
end
