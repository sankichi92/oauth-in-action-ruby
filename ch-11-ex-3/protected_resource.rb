# frozen_string_literal: true

require 'openssl'

require 'jwt'
require 'sinatra'
require 'sinatra/json'

SHARED_TOKEN_SECRET = 'shared OAuth token secret!'

RESOURCE = {
  name: 'Protected Resource',
  description: 'This data has been protected by OAuth 2.0',
}.freeze

RSA_KEY = <<~PEM
  -----BEGIN PUBLIC KEY-----
  MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2pZzFsNJZV1pC3TSuD0x
  YbsjgNN+oM1uGjphK/ZOHfmTS/1dSl2icr1bjV/T+oP8uy/LD5JHOxPvZhf9bgLx
  BtkBA19jr3l86k/wKQaThVnoeyE1dhUSd9qDvtWDuyzjg78st8Q9/M5Dk7Kzs/Ha
  VQvZNFkczOnEHGKXWpFKOdlE5WhDLrBFgGeNt+vdvQE9MJGNnPXrRAVDYlkKPpLw
  L8HtmZqY+BeBUlk1MAMoRBn0PT0qzV2OXJnnev5UM2MO9lyMeWJaHw/7k/Ybf6gG
  8C/gc0goZwaavToM5bv2qRHckP/PuqfDsdgMGKVXm9GLLz5RqBqvvYLX263e7THY
  WwIDAQAB
  -----END PUBLIC KEY-----
PEM

set :port, 9002

before do
  token = request.env['HTTP_AUTHORIZATION']&.slice(%r{^Bearer +([a-z0-9\-._‾+/]+=*)}i, 1) || params[:access_token]
  logger.info "Incoming token: #{token}"
  halt 401 if token.nil?

  begin
    payload, _header = JWT.decode(
      token,
      OpenSSL::PKey::RSA.new(RSA_KEY),
      true,
      {
        algorithm: 'RS256',
        iss: 'http://localhost:9001/',
        aud: "http://#{settings.bind}:#{settings.port}/",
        verify_iss: true,
        verify_aud: true,
        verify_iat: true,
      },
    )
  rescue JWT::DecodeError => e
    logger.error e
    halt 401
  end

  logger.info payload.inspect
end

post '/resource' do
  json RESOURCE
end
