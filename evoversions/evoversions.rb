#!/bin/env ruby

require 'cgi'

# Get the 'q' parameter out of the incoming Query String
cgi = CGI.new
os_release = cgi.params["os_release"].first

Dir.chdir("versions") do
  puts Dir.pwd
  Dir.each_child(Dir.pwd) do |x|
    puts x.class.name
  end
end