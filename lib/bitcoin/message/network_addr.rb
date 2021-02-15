require 'ipaddr'
require 'base32'

module Bitcoin
  module Message

    NETWORK_ID = {ipv4: 0x01, ipv6: 0x02, tor_v2: 0x03, tor_v3: 0x04, i2p: 0x05, cjdns: 0x06}
    INTERNAL_IN_IPV6_PREFIX = "fd6b:88c0:8724"

    class NetworkAddr

      TYPE = {legacy: 0x01, addr_v2: 0x02}

      # unix time.
      # Nodes advertising their own IP address set this to the current time.
      # Nodes advertising IP addresses they’ve connected to set this to the last time they connected to that node.
      # Other nodes just relaying the IP address should not change the time. Nodes can use the time field to avoid relaying old addr messages.
      attr_accessor :time

      # The services the node advertised in its version message.
      attr_accessor :services

      attr_accessor :net # network ID that defined by BIP-155

      # Network address. The interpretation depends on networkID.
      # If ipv4 or ipv6 this field is a IPAddr object, otherwise hex string.
      attr_accessor :addr

      attr_accessor :port

      attr_reader :skip_time

      def initialize(ip: '127.0.0.1', port: Bitcoin.chain_params.default_port,
                     services: DEFAULT_SERVICE_FLAGS, time: Time.now.to_i, net: NETWORK_ID[:ipv4])
        @time = time
        @port = port
        @services = services
        @net = net
        case net
        when NETWORK_ID[:ipv4], NETWORK_ID[:ipv6]
          @addr = IPAddr.new(ip) if ip
        end
      end

      # Parse addr payload
      # @param [String] payload payload of addr
      # @param [Integer] type Address format type
      # @return [NetworkAddr]
      def self.parse_from_payload(payload, type: TYPE[:legacy])
        case type
        when TYPE[:legacy]
          load_legacy_payload(payload)
        when TYPE[:addr_v2]
          load_addr_v2_payload(payload)
        else
          raise Bitcoin::Message::Error, "Unknown type: #{type}."
        end
      end

      def self.local_addr
        addr = new
        addr.addr = IPAddr.new('127.0.0.1')
        addr.port = Bitcoin.chain_params.default_port
        addr.services = DEFAULT_SERVICE_FLAGS
        addr
      end

      # Show addr string. e.g 127.0.0.1
      def addr_string
        case net
        when NETWORK_ID[:ipv4]
          addr.native
        when NETWORK_ID[:ipv6]
          if addr.to_s.start_with?(INTERNAL_IN_IPV6_PREFIX)
            Base32.encode(addr.hton[6..-1]).downcase.delete('=') + ".internal"
          else
            addr.to_s
          end
        when NETWORK_ID[:tor_v2]
          Base32.encode(addr.htb).downcase + ".onion"
        when NETWORK_ID[:tor_v3]
          # TORv3 onion_address = base32(PUBKEY | CHECKSUM | VERSION) + ".onion"
          pubkey = addr.htb
          checksum = OpenSSL::Digest.new('SHA3-256').digest('.onion checksum' + pubkey + "\x03")
          Base32.encode(pubkey + checksum[0...2] + "\x03").downcase + ".onion"
        when NETWORK_ID[:i2p]
          Base32.encode(addr.htb).downcase.delete('=') + ".b32.i2p"
        when NETWORK_ID[:cjdns]
          addr.to_s
        end
      end

      def to_payload(skip_time = false, type: TYPE[:legacy])
        case type
        when TYPE[:legacy]
          legacy_payload(skip_time)
        when TYPE[:addr_v2]
          v2_payload
        else
          raise Bitcoin::Message::Error, "Unknown type: #{type}."
        end
      end

      # Load addr payload with legacy format.
      def self.load_legacy_payload(payload)
        buf = payload.is_a?(String) ? StringIO.new(payload) : payload
        has_time = buf.size > 26
        addr = NetworkAddr.new(time: nil)
        addr.time = buf.read(4).unpack1('V') if has_time
        addr.services = buf.read(8).unpack1('Q')
        addr.addr = IPAddr::new_ntoh(buf.read(16))
        addr.port = buf.read(2).unpack1('n')
        addr
      end

      # Load addr payload with addr v2 format.
      def self.load_addr_v2_payload(payload)
        buf = payload.is_a?(String) ? StringIO.new(payload) : payload
        addr = NetworkAddr.new(time: buf.read(4).unpack1('V'))
        addr.services = Bitcoin.unpack_var_int_from_io(buf)
        addr.net = buf.read(1).unpack1('C')
        raise Bitcoin::Message::Error, "Unknown network id: #{addr.net}" unless NETWORK_ID.value?(addr.net)
        addr_len = Bitcoin.unpack_var_int_from_io(buf)
        addr.addr = case addr.net 
                    when NETWORK_ID[:ipv4]
                      raise Bitcoin::Message::Error, "Invalid IPv4 address." unless addr_len == 4
                      IPAddr::new_ntoh(buf.read(addr_len))
                    when NETWORK_ID[:ipv6]
                      raise Bitcoin::Message::Error, "Invalid IPv6 address." unless addr_len == 16
                      a = IPAddr::new_ntoh(buf.read(addr_len))
                      raise Bitcoin::Message::Error, "Invalid IPv6 address." if a.ipv4_mapped?
                      a
                    when NETWORK_ID[:tor_v2]
                      raise Bitcoin::Message::Error, "Invalid Tor v2 address." unless addr_len == 10
                      buf.read(addr_len).bth
                    when NETWORK_ID[:tor_v3]
                      raise Bitcoin::Message::Error, "Invalid Tor v3 address." unless addr_len == 32
                      buf.read(addr_len).bth
                    when NETWORK_ID[:i2p]
                      raise Bitcoin::Message::Error, "Invalid I2P address." unless addr_len == 32
                      buf.read(addr_len).bth
                    when NETWORK_ID[:cjdns]
                      raise Bitcoin::Message::Error, "Invalid CJDNS address." unless addr_len == 16
                      a = IPAddr::new_ntoh(buf.read(addr_len))
                      raise Bitcoin::Message::Error, "Invalid CJDNS address." unless a.to_s.start_with?('fc00:')
                      a
                    end
        addr.port = buf.read(2).unpack1('n')
        addr
      end

      def legacy_payload(skip_time)
        p = ''
        p << [time].pack('V') unless skip_time
        ip = addr.ipv4? ? addr.ipv4_mapped : addr
        p << [services].pack('Q') << ip.hton << [port].pack('n')
      end

      def v2_payload
        p = [time].pack('V')
        p << Bitcoin.pack_var_int(services)
        p << [net].pack('C')
        case net
        when NETWORK_ID[:ipv4]
          p << Bitcoin.pack_var_int(4)
          p << addr.to_i.to_s(16).htb
        when NETWORK_ID[:ipv6]
          p << Bitcoin.pack_var_int(16)
          p << addr.hton
        when NETWORK_ID[:tor_v2]
          p << Bitcoin.pack_var_int(10)
        when NETWORK_ID[:tor_v3]
          p << Bitcoin.pack_var_int(32)
        when NETWORK_ID[:i2p]
          p << Bitcoin.pack_var_int(32)
        when NETWORK_ID[:cjdns]
          p << Bitcoin.pack_var_int(16)
        end
        p << [port].pack('n')
        p
      end

    end

  end
end
