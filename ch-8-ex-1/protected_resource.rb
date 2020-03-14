# frozen_string_literal: true

require 'sinatra'
require 'sinatra/required_params'

require_relative '../lib/pseudo_database'

set :port, 9002

$db = PseudoDatabase.new(File.expand_path('../oauth-in-action-code/exercises/ch-8-ex-1/database.nosql', __dir__))

before do
  token = request.env['HTTP_AUTHORIZATION']&.slice(%r{^Bearer +([a-z0-9\-._‾+/]+=*)}i, 1) || params[:access_token]
  logger.info "Incoming token: #{token}"
  halt 401 if token.nil?

  @access_token = $db.find { |row| row[:access_token] == token }
  halt 401 if @access_token.nil?
end

get '/helloWorld' do
  required_params :language

  case params[:language]
  when 'en'
    'Hello World'
  when 'de'
    'Hello Welt'
  when 'it'
    'Ciao Mondo'
  when 'fr'
    'Bonjour monde'
  when 'es'
    'Hola mundo'
  else
    halt 400, "Invalid language: #{params[:language]}"
  end
end
