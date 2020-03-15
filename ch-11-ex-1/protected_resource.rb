# frozen_string_literal: true

require 'base64'
require 'json'

require 'sinatra'
require 'sinatra/json'

set :port, 9002

before do
  token = request.env['HTTP_AUTHORIZATION']&.slice(%r{^Bearer +([a-z0-9\-._‾+/]+=*)}i, 1) || params[:access_token]
  logger.info "Incoming token: #{token}"
  halt 401 if token.nil?

  _encoded_header, encoded_payload, = token.split('.')
  payload = JSON.parse(Base64.urlsafe_decode64(encoded_payload), symbolize_names: true)
  logger.info "JWT payload: #{payload}"

  now = Time.now

  halt 401 if payload[:iss] != 'http://localhost:9001/'
  halt 401 unless payload[:aud].include?("http://#{settings.bind}:#{settings.port}/")
  halt 401 if payload[:iat] > now.to_i || payload[:exp] < now.to_i
end

post '/resource' do
  json(
    name: 'Protected Resource',
    description: 'This data has been protected by OAuth 2.0',
  )
end
