# frozen_string_literal: true

require 'sinatra'
require 'sinatra/json'
require 'sinatra/required_params'

require_relative '../lib/pseudo_database'

$db = PseudoDatabase.new(File.expand_path('../oauth-in-action-code/exercises/ch-8-ex-1/database.nosql', __dir__))

set :port, 9002

before do
  token = request.env['HTTP_AUTHORIZATION']&.slice(%r{^Bearer +([a-z0-9\-._‾+/]+=*)}i, 1) || params[:access_token]
  logger.info "Incoming token: #{token}"
  halt 401 if token.nil? || $db.none? { |row| row[:access_token] == token }
end

get '/helloWorld' do
  required_params :language

  greeting = case params[:language]
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
               "Invalid language: #{escape(params[:language])}"
             end

  headers 'X-Content-Type-Options' => 'nosniff', 'X-XSS-Protection' => '1; mode=block'
  json greeting: greeting
end
