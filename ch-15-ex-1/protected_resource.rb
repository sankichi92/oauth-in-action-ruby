# frozen_string_literal: true

require 'json'
require 'net/http'
require 'uri'

require 'jwt'
require 'sinatra'
require 'sinatra/json'

INTROSPECTION_ENDPOINT = 'http://localhost:9001/introspect'

RESOURCE_ID = 'protected-resource-1'
RESOURCE_SECRET = 'protected-resource-secret-1'

set :port, 9002

before do
  token = request.env['HTTP_AUTHORIZATION']&.slice(/^PoP +(\S+)/i, 1) || params[:pop_access_token]
  logger.info "Incoming token: #{token}"
  halt 401 if token.nil?

  payload, _header = JWT.decode(token, nil, false)

  introspection_uri = URI.parse(INTROSPECTION_ENDPOINT)
  introspection_uri.user = RESOURCE_ID
  introspection_uri.password = RESOURCE_SECRET

  logger.info 'Introspecting token'
  response = Net::HTTP.post_form(introspection_uri, { token: payload['at'] })

  case response
  when Net::HTTPSuccess
    logger.info "Got introspection response: #{response.body}"
    response_body = JSON.parse(response.body, symbolize_names: true)
    halt 401 unless response_body[:active]

    begin
      payload, _header = JWT.decode(token, nil, true, { algorithm: 'RS256', jwks: { keys: [response_body[:access_token_key]] } })
      halt 401 if payload['m'] != request.request_method || payload['u'] != "#{request.host}:#{request.port}" || payload['p'] != request.path_info
    rescue JWT::JWKError, JWT::DecodeError => e
      logger.info e
      halt 401
    end
  else
    halt "Unable to introspect token: #{response.code} #{response.message}\n#{response.body}"
  end
end

post '/resource' do
  json(
    name: 'Protected Resource',
    description: 'This data has been protected by OAuth 2.0',
  )
end
