module Bitcoin
  module Message

    # inv message
    # https://bitcoin.org/en/developer-reference#inv
    class Inv < Base
      include InventoriesParser
      extend InventoriesParser

      COMMAND = 'inv'

      attr_reader :inventories

      def initialize(inventories = [])
        @inventories = inventories
      end

    end

  end
end