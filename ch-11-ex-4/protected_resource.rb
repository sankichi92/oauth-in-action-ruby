# frozen_string_literal: true

require 'json'
require 'net/http'
require 'uri'

require 'sinatra'
require 'sinatra/json'

INTROSPECTION_ENDPOINT = 'http://localhost:9001/introspect'

RESOURCE_ID = 'protected-resource-1'
RESOURCE_SECRET = 'protected-resource-secret-1'

set :port, 9002

before do
  token = request.env['HTTP_AUTHORIZATION']&.slice(%r{^Bearer +([a-z0-9\-._‾+/]+=*)}i, 1) || params[:access_token]
  logger.info "Incoming token: #{token}"
  halt 401 if token.nil?

  introspection_uri = URI.parse(INTROSPECTION_ENDPOINT)
  introspection_uri.user = RESOURCE_ID
  introspection_uri.password = RESOURCE_SECRET

  logger.info 'Introspecting token'
  response = Net::HTTP.post_form(introspection_uri, { token: token })

  case response
  when Net::HTTPSuccess
    logger.info "Got introspection response: #{response.body}"
    access_token = JSON.parse(response.body, symbolize_names: true)
    halt 401 unless access_token[:active]
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
