require 'ipaddr'

module Bitcoin
  module Message

    class NetworkAddr

      # unix time.
      # Nodes advertising their own IP address set this to the current time.
      # Nodes advertising IP addresses they’ve connected to set this to the last time they connected to that node.
      # Other nodes just relaying the IP address should not change the time. Nodes can use the time field to avoid relaying old addr messages.
      attr_accessor :time

      # The services the node advertised in its version message.
      attr_accessor :services

      attr_accessor :ip_addr # IPAddr

      attr_accessor :port

      attr_reader :skip_time

      def initialize(ip: '127.0.0.1', port: Bitcoin.chain_params.default_port, services: DEFAULT_SERVICE_FLAGS, time: Time.now.to_i)
        @time = time
        @ip_addr = IPAddr.new(ip)
        @port = port
        @services = services
      end

      def self.parse_from_payload(payload)
        buf = payload.is_a?(String) ? StringIO.new(payload) : payload
        has_time = buf.size > 26
        addr = new(time: nil)
        addr.time = buf.read(4).unpack('V').first if has_time
        addr.services = buf.read(8).unpack('Q').first
        addr.ip_addr = IPAddr::new_ntoh(buf.read(16))
        addr.port = buf.read(2).unpack('n').first
        addr
      end

      def self.local_addr
        addr = new
        addr.ip_addr = IPAddr.new('127.0.0.1')
        addr.port = Bitcoin.chain_params.default_port
        addr.services = DEFAULT_SERVICE_FLAGS
        addr
      end

      def ip
        ip_addr.ipv4_mapped? ? ip_addr.native : ip_addr.to_s
      end

      def to_payload(skip_time = false)
        p = ''
        p << [time].pack('V') unless skip_time
        addr = ip_addr.ipv4? ? ip_addr.ipv4_mapped : ip_addr
        p << [services].pack('Q') << addr.hton << [port].pack('n')
      end

    end

  end
end
