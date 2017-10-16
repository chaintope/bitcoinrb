require 'evma_httpserver'
require 'json'

module Bitcoin
  module RPC

    # Bitcoinrb RPC server.
    class HttpServer < EM::Connection
      include EM::HttpServer
      include RequestHandler

      attr_reader :node
      attr_accessor :logger

      def initialize(node)
        @node = node
        @logger = Bitcoin::Logger.create(:debug)
      end

      def post_init
        super
        logger.debug 'start http server.'
      end

      def self.run(node, port = 8332)
        EM.start_server('0.0.0.0', port, HttpServer, node)
      end

      def process_http_request
        params = JSON.parse(@http_post_content)
        command = params['method']
        logger.debug("process http request. command = #{command}")
        response = EM::DelegatedHttpResponse.new(self)
        response.status = 200
        response.content_type 'application/json'
        response.content = send(command).to_json
        response.send_response
      end

    end

  end
end
