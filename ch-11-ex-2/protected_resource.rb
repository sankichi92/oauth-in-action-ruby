# frozen_string_literal: true

require 'jwt'
require 'sinatra'
require 'sinatra/json'

SHARED_TOKEN_SECRET = 'shared OAuth token secret!'

set :port, 9002

before do
  token = request.env['HTTP_AUTHORIZATION']&.slice(%r{^Bearer +([a-z0-9\-._‾+/]+=*)}i, 1) || params[:access_token]
  logger.info "Incoming token: #{token}"
  halt 401 if token.nil?

  begin
    payload, _header = JWT.decode(
      token,
      SHARED_TOKEN_SECRET,
      true,
      {
        algorithm: 'HS256',
        iss: 'http://localhost:9001/',
        aud: "http://#{settings.bind}:#{settings.port}/",
        verify_iss: true,
        verify_aud: true,
        verify_iat: true,
      },
    )
    logger.info "JWT payload: #{payload}"
  rescue JWT::DecodeError => e
    logger.info e.inspect
    halt 401
  end
end

post '/resource' do
  json(
    name: 'Protected Resource',
    description: 'This data has been protected by OAuth 2.0',
  )
end
