module Bitcoin
  module Message

    # Default P2P message handler.
    class Handler

      attr_reader :logger
      attr_reader :conn

      def initialize(conn, logger = Bitcoin::Logger.create(:parser))
        @conn = conn
        @logger = logger
      end

      # handle p2p message.
      def handle(message)
        logger.info "handle message #{message.bth}"
        begin
          parse(message)
        rescue Error => e
          logger.error("invalid header magic. #{e.message}")
          conn.close
        end
      end

      private

      def parse(message)
        command, payload, rest = parse_header(message)
        handle_command(command, payload)
        parse(rest) if rest && rest.bytesize > 0
      end

      def parse_header(message)
        head_magic = Bitcoin.chain_params.magic_head
        raise Error, "invalid message header. message = #{message}" if message.nil? || message.size < HEADER_SIZE

        magic, command, length, checksum = message.unpack('a4A12Va4')
        raise Error, "invalid header magic. #{magic.bth}" unless magic.bth == head_magic

        payload = message[HEADER_SIZE...(HEADER_SIZE + length)]
        raise Error, "header checksum mismatch. #{checksum.bth}" unless Bitcoin.double_sha256(payload)[0...4] == checksum

        rest = message[(HEADER_SIZE + length)..-1]
        [command, payload, rest]
      end

      def handle_command(command, payload)
        logger.info("process command #{command}. payload = #{payload.bth}")
        case command
        when Version::COMMAND
          on_version(Version.parse_from_payload(payload))
        when VerAck::COMMAND
          on_ver_ack
        when SendHeaders::COMMAND
          on_send_headers
        when FeeFilter::COMMAND
          on_fee_filter(FeeFilter.parse_from_payload(payload))
        when Ping::COMMAND
          on_ping(Ping.parse_from_payload(payload))
        when Pong::COMMAND
          on_pong(Pong.parse_from_payload(payload))
        when GetHeaders::COMMAND
          on_get_headers(GetHeaders.parse_from_payload(payload))
        else
          conn.close
        end
      end

      def on_version(version)
        logger.info("receive version message. #{version.to_json}")
        conn.send_data(VerAck.new.to_pkt)
      end

      def on_ver_ack
        logger.info('receive verack message.')
        conn.handshake_done
      end

      def on_send_headers
        logger.info('receive sendheaders message.')
        conn.sendheaders = true
      end

      def on_fee_filter(fee_filter)
        logger.info('receive feefilter message.')
        conn.fee_rate = fee_filter.fee_rate
      end

      def on_ping(ping)
        logger.info('receive ping message')
        conn.send_data(ping.to_response)
      end

      def on_pong(pong)
        logger.info('receive pong message')
        # TODO calculate response
      end

      def on_get_headers(headers)
        logger.info('receive getheaders message')
        # TODO
      end

    end
  end
end