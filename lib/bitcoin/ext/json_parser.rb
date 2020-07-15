require 'json/pure'

module Bitcoin
  module Ext
    # Extension of JSON::Pure::Parser.
    # This class convert Float value to String value.
    class JsonParser < JSON::Pure::Parser

      def parse_value
        case
        when scan(FLOAT)
          self[1].to_s
        when scan(INTEGER)
          Integer(self[1])
        when scan(TRUE)
          true
        when scan(FALSE)
          false
        when scan(NULL)
          nil
        when !UNPARSED.equal?(string = parse_string)
          string
        when scan(ARRAY_OPEN)
          @current_nesting += 1
          ary = parse_array
          @current_nesting -= 1
          ary
        when scan(OBJECT_OPEN)
          @current_nesting += 1
          obj = parse_object
          @current_nesting -= 1
          obj
        when @allow_nan && scan(NAN)
          NaN
        when @allow_nan && scan(INFINITY)
          Infinity
        when @allow_nan && scan(MINUS_INFINITY)
          MinusInfinity
        else
          UNPARSED
        end
      end

    end
  end
end