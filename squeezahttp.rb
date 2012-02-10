require 'net/https'
require 'cgi'

class InvalidVarFormat < Exception
	def initialize(msg)
		@msg = msg
	end

	def to_s
		@msg
	end
end

class InvalidRequestException < Exception
end

class GeneralException < Exception
end

class HTTPException < Exception
	attr_accessor(:host, :url, :status, :msg)

	def initialize(host, url, status, msg)
		self.host = host
		self.url = url
		self.status = status
		self.msg = msg
	end

	def to_s
		str  = "HTTP Exception\n"
		str << "Host  :#{self.host}\n" if !self.host.nil?
		str << "URL   :#{self.url}\n" if !self.url.nil?
		str << "Status:#{self.status}\n" if !self.status.nil?
		str << "Msg   :#{self.msg}\n" if !self.msg.nil?
		str
	end
end

class HTTPRequestor
	attr_reader(:host, :port, :ssl, :url, :querystring, :hdrs, :method)
	@@placeholder = "X_X_X_X_X_X"

	def HTTPRequestor.help
    puts "http commands and variables"
		puts " variables"
    puts "  host   : target webserver"
    puts "  port   : port number"
    puts "  url    : target url"
    puts "  method : either POST or GET"
    puts "  ssl    : toggle SSL"
	end

	def help
		HTTPRequestor.help
	end

	def initialize(host, port, method, url, querystring, hdrs = nil, ssl = false, http_resp_ok = "200")
		@http_obj = nil
		@http_error_count = 0
		@host = host
		@port = port.to_i
		@ssl = ssl
		@method = method.upcase
		@url = url
		@querystring = querystring
		@http_resp_ok = http_resp_ok.split(/,/) if http_resp_ok
		@http_resp_ok ||= ["200"] #default value
		@hdrs = {} 
		@hdrs["Content-Type"] = "application/x-www-form-urlencoded"
		hdrs.each {|hdr| 
			(k,v) = hdr.split(/ *: */,2)
			raise InvalidVarFormat.new("HTTP header does not appear to contain a ':'. Offending line is '#{hdr}'") if !(k.is_a?(String) && v.is_a?(String))
			@hdrs[k] = v
		} if !hdrs.nil?

		raise InvalidRequestException, "Invalid host" if (@host.nil?)
		raise InvalidRequestException, "Invalid port" if (@port.nil? || @port > 65534 || @port < 0)
		raise InvalidRequestException, "Invalid SSL value" if (@ssl != true && @ssl != false)
		raise InvalidRequestException, "Invalid method (#{@method})." if (@method.nil? || !(@method == "POST" || @method == "GET"))
		raise InvalidRequestException, "No URL provided" if (@url.nil?)
		raise InvalidRequestException, "No querystring provided" if (@querystring.nil?)
		raise InvalidRequestException, "Querystring does not contain #{@@placeholder}. (#{@querystring})" if (@querystring !~ /#{@@placeholder}/)
	end

	def HTTPRequestor.getPlaceHolder
		@@placeholder
	end

	def connect
		@http_obj = Net::HTTP.new(@host, @port)
		if (@ssl)
			@http_obj.use_ssl = true
			@http_obj.verify_mode = OpenSSL::SSL::VERIFY_NONE
		end
		@http_obj.open_timeout = 60
		@http_obj.read_timeout = 600
		@http_obj.start
		Debug.print("HTTP connection started",2)
	end

	def disconnect
		@http_obj.finish
		@http_obj = nil
		Debug.print("HTTP connection stopped",2)
	end

	def send(query)
		if (@http_obj.nil? || @http_obj.started?)
			connect
		end

		if @method == "POST"
			response = @http_obj.post(@url, @querystring.sub(/#{@@placeholder}/, CGI.escape(query)), @hdrs)
		elsif @method == "GET"
			response = @http_obj.get(@url + "?" + @querystring.sub(/#{@@placeholder}/, CGI.escape(query)), @hdrs)
		end
		Debug.print(response.body,3)
		raise HTTPException.new(@host, @url, response.code, "Expected response not one of #{@http_resp_ok.join(' ')}") if @http_resp_ok.grep(/#{response.code.to_i}/).length == 0
		disconnect
		return response

		rescue TimeoutError
			@http_obj = nil
			@http_error_count += 1
			if @http_error_count < 3
				Debug.print("HTTP Timeout, retrying. If you're copying a large file, you'll probably want to up the read timeout",2)
				result = self.send(query)
				@http_error_count = 0
				return result
			else
				raise HTTPException.new(@host,@url,0,"connect() timed out.")
			end
		rescue SocketError => err
			@http_obj = nil
			raise HTTPException.new(@host,@url,0,"socket error: #{err.to_s}")
		rescue Errno::ECONNREFUSED
			@http_obj = nil
			raise HTTPException.new(@host, @url, 0, "connection refused")
		rescue => e
			@http_obj = nil
			raise HTTPException.new(@host, @url, 0, "Unknown connection problem: #{e.to_s}")
	end

	def host=(host)
		@host = host
		@http_obj = nil
	end

	def port=(port)
		@port = port.to_i
		raise InvalidRequestException, "Invalid port" if (@port.nil? || @port =~ /[^0-9]/ || @port > 65534 || @port < 0)
		@http_obj = nil
	end

	def ssl=(ssl)
		if ssl == "true"
			@ssl = true
		elsif ssl == "false"
			@ssl = false
		else
			raise InvalidRequestException, "Invalid SSL value" if (@ssl != true && @ssl != false)
		end
		@http_obj = nil
	end

end

