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

      attr_accessor :ip

      attr_accessor :port

      def initialize
        @time = Time.now.to_i
        @services = Bitcoin::Message::SERVICE_FLAGS[:network]
      end

      def self.parse_from_payload(payload)
        buf = payload.is_a?(String) ? StringIO.new(payload) : payload
        addr = new
        addr.time = buf.read(4).unpack('V').first
        addr.services = buf.read(8).unpack('Q').first
        ip = IPAddr::new_ntoh(buf.read(16))
        addr.ip = ip.ipv4_mapped? ? ip.native : ip.to_s
        addr.port = buf.read(2).unpack('n').first
        addr
      end

      def to_payload
        ip_addr = IPAddr.new (ip)
        ip_addr = ip_addr.ipv4_mapped if ip_addr.ipv4?
        [time, services].pack('VQ') << ip_addr.hton << [port].pack('n')
      end

    end

  end
end
